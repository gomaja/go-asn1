// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

package tcap

import (
	"fmt"
	"math/big"

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

// TCMessage choice constants.
const (
	TCMessageChoiceUnidirectional = 1
	TCMessageChoiceBegin          = 2
	TCMessageChoiceEnd            = 3
	TCMessageChoiceContinue       = 4
	TCMessageChoiceAbort          = 5
)

// TCMessage represents the ASN.1 CHOICE type TCMessage.
type TCMessage struct {
	Choice         int
	berOriginal_   []byte                        `json:"-"`
	berSnapshot_   []byte                        `json:"-"`
	Unidirectional *TCMessageUnidirectionalBound `json:"Unidirectional,omitempty"`
	Begin          *TCMessageBeginBound          `json:"Begin,omitempty"`
	End            *TCMessageEndBound            `json:"End,omitempty"`
	Continue       *TCMessageContinueBound       `json:"Continue,omitempty"`
	Abort          *Abort                        `json:"Abort,omitempty"`
}

// NewTCMessageUnidirectional creates a TCMessage with the unidirectional alternative.
func NewTCMessageUnidirectional(v TCMessageUnidirectionalBound) TCMessage {
	return TCMessage{
		Choice:         TCMessageChoiceUnidirectional,
		Unidirectional: &v,
	}
}

// NewTCMessageBegin creates a TCMessage with the begin alternative.
func NewTCMessageBegin(v TCMessageBeginBound) TCMessage {
	return TCMessage{
		Choice: TCMessageChoiceBegin,
		Begin:  &v,
	}
}

// NewTCMessageEnd creates a TCMessage with the end alternative.
func NewTCMessageEnd(v TCMessageEndBound) TCMessage {
	return TCMessage{
		Choice: TCMessageChoiceEnd,
		End:    &v,
	}
}

// NewTCMessageContinue creates a TCMessage with the continue alternative.
func NewTCMessageContinue(v TCMessageContinueBound) TCMessage {
	return TCMessage{
		Choice:   TCMessageChoiceContinue,
		Continue: &v,
	}
}

// NewTCMessageAbort creates a TCMessage with the abort alternative.
func NewTCMessageAbort(v Abort) TCMessage {
	return TCMessage{
		Choice: TCMessageChoiceAbort,
		Abort:  &v,
	}
}

// Unidirectional represents the ASN.1 type Unidirectional (SEQUENCE).
type Unidirectional struct {
	DialoguePortion  *DialoguePortion               `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *UnidirectionalComponentsBound `asn1:"tag:12,application,implicit"`
	ComponentsIndef_ bool                           `asn1:"-" json:"-"`
	berOriginal_     []byte                         `asn1:"-" json:"-"`
	berSnapshot_     []byte                         `asn1:"-" json:"-"`
}

// Begin represents the ASN.1 type Begin (SEQUENCE).
type Begin struct {
	Otid             OrigTransactionID     `asn1:""`
	DialoguePortion  *DialoguePortion      `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *BeginComponentsBound `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool                  `asn1:"-" json:"-"`
	berOriginal_     []byte                `asn1:"-" json:"-"`
	berSnapshot_     []byte                `asn1:"-" json:"-"`
}

// End represents the ASN.1 type End (SEQUENCE).
type End struct {
	Dtid             DestTransactionID   `asn1:""`
	DialoguePortion  *DialoguePortion    `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *EndComponentsBound `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool                `asn1:"-" json:"-"`
	berOriginal_     []byte              `asn1:"-" json:"-"`
	berSnapshot_     []byte              `asn1:"-" json:"-"`
}

// Continue represents the ASN.1 type Continue (SEQUENCE).
type Continue struct {
	Otid             OrigTransactionID        `asn1:""`
	Dtid             DestTransactionID        `asn1:""`
	DialoguePortion  *DialoguePortion         `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *ContinueComponentsBound `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool                     `asn1:"-" json:"-"`
	berOriginal_     []byte                   `asn1:"-" json:"-"`
	berSnapshot_     []byte                   `asn1:"-" json:"-"`
}

// Abort represents the ASN.1 type Abort (SEQUENCE).
type Abort struct {
	Dtid         DestTransactionID `asn1:""`
	Reason       *AbortReason      `asn1:",optional" json:"Reason,omitempty"`
	berOriginal_ []byte            `asn1:"-" json:"-"`
	berSnapshot_ []byte            `asn1:"-" json:"-"`
}

// DialoguePortion represents the ASN.1 EXTERNAL type DialoguePortion.
type DialoguePortion runtime.External

// OrigTransactionID represents the ASN.1 type OrigTransactionID (OCTET_STRING).
type OrigTransactionID = []byte

// DestTransactionID represents the ASN.1 type DestTransactionID (OCTET_STRING).
type DestTransactionID = []byte

// PAbortCause represents the ASN.1 INTEGER type P-AbortCause with named numbers.
type PAbortCause int64

const (
	PAbortCauseUnrecognizedMessageType          PAbortCause = 0
	PAbortCauseUnrecognizedTransactionID        PAbortCause = 1
	PAbortCauseBadlyFormattedTransactionPortion PAbortCause = 2
	PAbortCauseIncorrectTransactionPortion      PAbortCause = 3
	PAbortCauseResourceLimitation               PAbortCause = 4
)

func (v PAbortCause) String() string {
	switch v {
	case PAbortCauseUnrecognizedMessageType:
		return "unrecognizedMessageType"
	case PAbortCauseUnrecognizedTransactionID:
		return "unrecognizedTransactionID"
	case PAbortCauseBadlyFormattedTransactionPortion:
		return "badlyFormattedTransactionPortion"
	case PAbortCauseIncorrectTransactionPortion:
		return "incorrectTransactionPortion"
	case PAbortCauseResourceLimitation:
		return "resourceLimitation"
	default:
		return "unknown"
	}
}

// ComponentPortion represents the ASN.1 type ComponentPortion (SEQUENCE_OF).
type ComponentPortion struct {
	Values       []ComponentPortionElemBound `json:"Values"`
	berOriginal_ []byte                      `json:"-"`
	berSnapshot_ []byte                      `json:"-"`
}

// Component choice constants.
const (
	ComponentChoiceBasicROS            = 1
	ComponentChoiceReturnResultNotLast = 2
)

// Component represents the ASN.1 CHOICE type Component.
type Component struct {
	Choice              int
	berOriginal_        []byte                  `json:"-"`
	berSnapshot_        []byte                  `json:"-"`
	BasicROS            *ComponentBasicROSBound `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult           `json:"ReturnResultNotLast,omitempty"`
}

// NewComponentBasicROS creates a Component with the basicROS alternative.
func NewComponentBasicROS(v ComponentBasicROSBound) Component {
	return Component{
		Choice:   ComponentChoiceBasicROS,
		BasicROS: &v,
	}
}

// NewComponentReturnResultNotLast creates a Component with the returnResultNotLast alternative.
func NewComponentReturnResultNotLast(v ReturnResult) Component {
	return Component{
		Choice:              ComponentChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// TCInvokeIdSet choice constants.
const (
	TCInvokeIdSetChoicePresent = 1
	TCInvokeIdSetChoiceAbsent  = 2
)

// TCInvokeIdSet represents the ASN.1 CHOICE type TCInvokeIdSet.
type TCInvokeIdSet struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *int64    `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewTCInvokeIdSetPresent creates a TCInvokeIdSet with the present alternative.
func NewTCInvokeIdSetPresent(v int64) TCInvokeIdSet {
	return TCInvokeIdSet{
		Choice:  TCInvokeIdSetChoicePresent,
		Present: &v,
	}
}

// NewTCInvokeIdSetAbsent creates a TCInvokeIdSet with the absent alternative.
func NewTCInvokeIdSetAbsent(v struct{}) TCInvokeIdSet {
	return TCInvokeIdSet{
		Choice: TCInvokeIdSetChoiceAbsent,
		Absent: &v,
	}
}

// TCMessageUnidirectionalComponentsElemBasicROSInvokeBound represents the ASN.1 type TCMessage-unidirectional-components-Elem-basicROS-invoke-Bound (SEQUENCE).
type TCMessageUnidirectionalComponentsElemBasicROSInvokeBound struct {
	InvokeId     TCInvokeIdSet                                                     `asn1:""`
	LinkedId     *TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode       Code                                                              `asn1:""`
	Argument     *runtime.RawValue                                                 `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                                                            `asn1:"-" json:"-"`
	berSnapshot_ []byte                                                            `asn1:"-" json:"-"`
}

// TCMessageUnidirectionalComponentsElemBasicROSBound choice constants.
const (
	TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceInvoke       = 1
	TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnResult = 2
	TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnError  = 3
	TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReject       = 4
)

// TCMessageUnidirectionalComponentsElemBasicROSBound represents the ASN.1 CHOICE type TCMessage-unidirectional-components-Elem-basicROS-Bound.
type TCMessageUnidirectionalComponentsElemBasicROSBound struct {
	Choice       int
	berOriginal_ []byte                                                    `json:"-"`
	berSnapshot_ []byte                                                    `json:"-"`
	Invoke       *TCMessageUnidirectionalComponentsElemBasicROSInvokeBound `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult                                             `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError                                              `json:"ReturnError,omitempty"`
	Reject       *Reject                                                   `json:"Reject,omitempty"`
}

// NewTCMessageUnidirectionalComponentsElemBasicROSBoundInvoke creates a TCMessageUnidirectionalComponentsElemBasicROSBound with the invoke alternative.
func NewTCMessageUnidirectionalComponentsElemBasicROSBoundInvoke(v TCMessageUnidirectionalComponentsElemBasicROSInvokeBound) TCMessageUnidirectionalComponentsElemBasicROSBound {
	return TCMessageUnidirectionalComponentsElemBasicROSBound{
		Choice: TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceInvoke,
		Invoke: &v,
	}
}

// NewTCMessageUnidirectionalComponentsElemBasicROSBoundReturnResult creates a TCMessageUnidirectionalComponentsElemBasicROSBound with the returnResult alternative.
func NewTCMessageUnidirectionalComponentsElemBasicROSBoundReturnResult(v ReturnResult) TCMessageUnidirectionalComponentsElemBasicROSBound {
	return TCMessageUnidirectionalComponentsElemBasicROSBound{
		Choice:       TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewTCMessageUnidirectionalComponentsElemBasicROSBoundReturnError creates a TCMessageUnidirectionalComponentsElemBasicROSBound with the returnError alternative.
func NewTCMessageUnidirectionalComponentsElemBasicROSBoundReturnError(v ReturnError) TCMessageUnidirectionalComponentsElemBasicROSBound {
	return TCMessageUnidirectionalComponentsElemBasicROSBound{
		Choice:      TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnError,
		ReturnError: &v,
	}
}

// NewTCMessageUnidirectionalComponentsElemBasicROSBoundReject creates a TCMessageUnidirectionalComponentsElemBasicROSBound with the reject alternative.
func NewTCMessageUnidirectionalComponentsElemBasicROSBoundReject(v Reject) TCMessageUnidirectionalComponentsElemBasicROSBound {
	return TCMessageUnidirectionalComponentsElemBasicROSBound{
		Choice: TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReject,
		Reject: &v,
	}
}

// TCMessageUnidirectionalComponentsElemBound choice constants.
const (
	TCMessageUnidirectionalComponentsElemBoundChoiceBasicROS            = 1
	TCMessageUnidirectionalComponentsElemBoundChoiceReturnResultNotLast = 2
)

// TCMessageUnidirectionalComponentsElemBound represents the ASN.1 CHOICE type TCMessage-unidirectional-components-Elem-Bound.
type TCMessageUnidirectionalComponentsElemBound struct {
	Choice              int
	berOriginal_        []byte                                              `json:"-"`
	berSnapshot_        []byte                                              `json:"-"`
	BasicROS            *TCMessageUnidirectionalComponentsElemBasicROSBound `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult                                       `json:"ReturnResultNotLast,omitempty"`
}

// NewTCMessageUnidirectionalComponentsElemBoundBasicROS creates a TCMessageUnidirectionalComponentsElemBound with the basicROS alternative.
func NewTCMessageUnidirectionalComponentsElemBoundBasicROS(v TCMessageUnidirectionalComponentsElemBasicROSBound) TCMessageUnidirectionalComponentsElemBound {
	return TCMessageUnidirectionalComponentsElemBound{
		Choice:   TCMessageUnidirectionalComponentsElemBoundChoiceBasicROS,
		BasicROS: &v,
	}
}

// NewTCMessageUnidirectionalComponentsElemBoundReturnResultNotLast creates a TCMessageUnidirectionalComponentsElemBound with the returnResultNotLast alternative.
func NewTCMessageUnidirectionalComponentsElemBoundReturnResultNotLast(v ReturnResult) TCMessageUnidirectionalComponentsElemBound {
	return TCMessageUnidirectionalComponentsElemBound{
		Choice:              TCMessageUnidirectionalComponentsElemBoundChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// TCMessageUnidirectionalComponentsBound represents the ASN.1 type TCMessage-unidirectional-components-Bound (SEQUENCE_OF).
type TCMessageUnidirectionalComponentsBound struct {
	Values       []TCMessageUnidirectionalComponentsElemBound `json:"Values"`
	berOriginal_ []byte                                       `json:"-"`
	berSnapshot_ []byte                                       `json:"-"`
}

// TCMessageUnidirectionalBound represents the ASN.1 type TCMessage-unidirectional-Bound (SEQUENCE).
type TCMessageUnidirectionalBound struct {
	DialoguePortion  *DialoguePortion                        `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *TCMessageUnidirectionalComponentsBound `asn1:"tag:12,application,implicit"`
	ComponentsIndef_ bool                                    `asn1:"-" json:"-"`
	berOriginal_     []byte                                  `asn1:"-" json:"-"`
	berSnapshot_     []byte                                  `asn1:"-" json:"-"`
}

// TCMessageBeginComponentsElemBasicROSInvokeBound represents the ASN.1 type TCMessage-begin-components-Elem-basicROS-invoke-Bound (SEQUENCE).
type TCMessageBeginComponentsElemBasicROSInvokeBound struct {
	InvokeId     TCInvokeIdSet                                            `asn1:""`
	LinkedId     *TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode       Code                                                     `asn1:""`
	Argument     *runtime.RawValue                                        `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                                                   `asn1:"-" json:"-"`
	berSnapshot_ []byte                                                   `asn1:"-" json:"-"`
}

// TCMessageBeginComponentsElemBasicROSBound choice constants.
const (
	TCMessageBeginComponentsElemBasicROSBoundChoiceInvoke       = 1
	TCMessageBeginComponentsElemBasicROSBoundChoiceReturnResult = 2
	TCMessageBeginComponentsElemBasicROSBoundChoiceReturnError  = 3
	TCMessageBeginComponentsElemBasicROSBoundChoiceReject       = 4
)

// TCMessageBeginComponentsElemBasicROSBound represents the ASN.1 CHOICE type TCMessage-begin-components-Elem-basicROS-Bound.
type TCMessageBeginComponentsElemBasicROSBound struct {
	Choice       int
	berOriginal_ []byte                                           `json:"-"`
	berSnapshot_ []byte                                           `json:"-"`
	Invoke       *TCMessageBeginComponentsElemBasicROSInvokeBound `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult                                    `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError                                     `json:"ReturnError,omitempty"`
	Reject       *Reject                                          `json:"Reject,omitempty"`
}

// NewTCMessageBeginComponentsElemBasicROSBoundInvoke creates a TCMessageBeginComponentsElemBasicROSBound with the invoke alternative.
func NewTCMessageBeginComponentsElemBasicROSBoundInvoke(v TCMessageBeginComponentsElemBasicROSInvokeBound) TCMessageBeginComponentsElemBasicROSBound {
	return TCMessageBeginComponentsElemBasicROSBound{
		Choice: TCMessageBeginComponentsElemBasicROSBoundChoiceInvoke,
		Invoke: &v,
	}
}

// NewTCMessageBeginComponentsElemBasicROSBoundReturnResult creates a TCMessageBeginComponentsElemBasicROSBound with the returnResult alternative.
func NewTCMessageBeginComponentsElemBasicROSBoundReturnResult(v ReturnResult) TCMessageBeginComponentsElemBasicROSBound {
	return TCMessageBeginComponentsElemBasicROSBound{
		Choice:       TCMessageBeginComponentsElemBasicROSBoundChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewTCMessageBeginComponentsElemBasicROSBoundReturnError creates a TCMessageBeginComponentsElemBasicROSBound with the returnError alternative.
func NewTCMessageBeginComponentsElemBasicROSBoundReturnError(v ReturnError) TCMessageBeginComponentsElemBasicROSBound {
	return TCMessageBeginComponentsElemBasicROSBound{
		Choice:      TCMessageBeginComponentsElemBasicROSBoundChoiceReturnError,
		ReturnError: &v,
	}
}

// NewTCMessageBeginComponentsElemBasicROSBoundReject creates a TCMessageBeginComponentsElemBasicROSBound with the reject alternative.
func NewTCMessageBeginComponentsElemBasicROSBoundReject(v Reject) TCMessageBeginComponentsElemBasicROSBound {
	return TCMessageBeginComponentsElemBasicROSBound{
		Choice: TCMessageBeginComponentsElemBasicROSBoundChoiceReject,
		Reject: &v,
	}
}

// TCMessageBeginComponentsElemBound choice constants.
const (
	TCMessageBeginComponentsElemBoundChoiceBasicROS            = 1
	TCMessageBeginComponentsElemBoundChoiceReturnResultNotLast = 2
)

// TCMessageBeginComponentsElemBound represents the ASN.1 CHOICE type TCMessage-begin-components-Elem-Bound.
type TCMessageBeginComponentsElemBound struct {
	Choice              int
	berOriginal_        []byte                                     `json:"-"`
	berSnapshot_        []byte                                     `json:"-"`
	BasicROS            *TCMessageBeginComponentsElemBasicROSBound `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult                              `json:"ReturnResultNotLast,omitempty"`
}

// NewTCMessageBeginComponentsElemBoundBasicROS creates a TCMessageBeginComponentsElemBound with the basicROS alternative.
func NewTCMessageBeginComponentsElemBoundBasicROS(v TCMessageBeginComponentsElemBasicROSBound) TCMessageBeginComponentsElemBound {
	return TCMessageBeginComponentsElemBound{
		Choice:   TCMessageBeginComponentsElemBoundChoiceBasicROS,
		BasicROS: &v,
	}
}

// NewTCMessageBeginComponentsElemBoundReturnResultNotLast creates a TCMessageBeginComponentsElemBound with the returnResultNotLast alternative.
func NewTCMessageBeginComponentsElemBoundReturnResultNotLast(v ReturnResult) TCMessageBeginComponentsElemBound {
	return TCMessageBeginComponentsElemBound{
		Choice:              TCMessageBeginComponentsElemBoundChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// TCMessageBeginComponentsBound represents the ASN.1 type TCMessage-begin-components-Bound (SEQUENCE_OF).
type TCMessageBeginComponentsBound struct {
	Values       []TCMessageBeginComponentsElemBound `json:"Values"`
	berOriginal_ []byte                              `json:"-"`
	berSnapshot_ []byte                              `json:"-"`
}

// TCMessageBeginBound represents the ASN.1 type TCMessage-begin-Bound (SEQUENCE).
type TCMessageBeginBound struct {
	Otid             OrigTransactionID              `asn1:""`
	DialoguePortion  *DialoguePortion               `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *TCMessageBeginComponentsBound `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool                           `asn1:"-" json:"-"`
	berOriginal_     []byte                         `asn1:"-" json:"-"`
	berSnapshot_     []byte                         `asn1:"-" json:"-"`
}

// TCMessageEndComponentsElemBasicROSInvokeBound represents the ASN.1 type TCMessage-end-components-Elem-basicROS-invoke-Bound (SEQUENCE).
type TCMessageEndComponentsElemBasicROSInvokeBound struct {
	InvokeId     TCInvokeIdSet                                          `asn1:""`
	LinkedId     *TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode       Code                                                   `asn1:""`
	Argument     *runtime.RawValue                                      `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                                                 `asn1:"-" json:"-"`
	berSnapshot_ []byte                                                 `asn1:"-" json:"-"`
}

// TCMessageEndComponentsElemBasicROSBound choice constants.
const (
	TCMessageEndComponentsElemBasicROSBoundChoiceInvoke       = 1
	TCMessageEndComponentsElemBasicROSBoundChoiceReturnResult = 2
	TCMessageEndComponentsElemBasicROSBoundChoiceReturnError  = 3
	TCMessageEndComponentsElemBasicROSBoundChoiceReject       = 4
)

// TCMessageEndComponentsElemBasicROSBound represents the ASN.1 CHOICE type TCMessage-end-components-Elem-basicROS-Bound.
type TCMessageEndComponentsElemBasicROSBound struct {
	Choice       int
	berOriginal_ []byte                                         `json:"-"`
	berSnapshot_ []byte                                         `json:"-"`
	Invoke       *TCMessageEndComponentsElemBasicROSInvokeBound `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult                                  `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError                                   `json:"ReturnError,omitempty"`
	Reject       *Reject                                        `json:"Reject,omitempty"`
}

// NewTCMessageEndComponentsElemBasicROSBoundInvoke creates a TCMessageEndComponentsElemBasicROSBound with the invoke alternative.
func NewTCMessageEndComponentsElemBasicROSBoundInvoke(v TCMessageEndComponentsElemBasicROSInvokeBound) TCMessageEndComponentsElemBasicROSBound {
	return TCMessageEndComponentsElemBasicROSBound{
		Choice: TCMessageEndComponentsElemBasicROSBoundChoiceInvoke,
		Invoke: &v,
	}
}

// NewTCMessageEndComponentsElemBasicROSBoundReturnResult creates a TCMessageEndComponentsElemBasicROSBound with the returnResult alternative.
func NewTCMessageEndComponentsElemBasicROSBoundReturnResult(v ReturnResult) TCMessageEndComponentsElemBasicROSBound {
	return TCMessageEndComponentsElemBasicROSBound{
		Choice:       TCMessageEndComponentsElemBasicROSBoundChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewTCMessageEndComponentsElemBasicROSBoundReturnError creates a TCMessageEndComponentsElemBasicROSBound with the returnError alternative.
func NewTCMessageEndComponentsElemBasicROSBoundReturnError(v ReturnError) TCMessageEndComponentsElemBasicROSBound {
	return TCMessageEndComponentsElemBasicROSBound{
		Choice:      TCMessageEndComponentsElemBasicROSBoundChoiceReturnError,
		ReturnError: &v,
	}
}

// NewTCMessageEndComponentsElemBasicROSBoundReject creates a TCMessageEndComponentsElemBasicROSBound with the reject alternative.
func NewTCMessageEndComponentsElemBasicROSBoundReject(v Reject) TCMessageEndComponentsElemBasicROSBound {
	return TCMessageEndComponentsElemBasicROSBound{
		Choice: TCMessageEndComponentsElemBasicROSBoundChoiceReject,
		Reject: &v,
	}
}

// TCMessageEndComponentsElemBound choice constants.
const (
	TCMessageEndComponentsElemBoundChoiceBasicROS            = 1
	TCMessageEndComponentsElemBoundChoiceReturnResultNotLast = 2
)

// TCMessageEndComponentsElemBound represents the ASN.1 CHOICE type TCMessage-end-components-Elem-Bound.
type TCMessageEndComponentsElemBound struct {
	Choice              int
	berOriginal_        []byte                                   `json:"-"`
	berSnapshot_        []byte                                   `json:"-"`
	BasicROS            *TCMessageEndComponentsElemBasicROSBound `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult                            `json:"ReturnResultNotLast,omitempty"`
}

// NewTCMessageEndComponentsElemBoundBasicROS creates a TCMessageEndComponentsElemBound with the basicROS alternative.
func NewTCMessageEndComponentsElemBoundBasicROS(v TCMessageEndComponentsElemBasicROSBound) TCMessageEndComponentsElemBound {
	return TCMessageEndComponentsElemBound{
		Choice:   TCMessageEndComponentsElemBoundChoiceBasicROS,
		BasicROS: &v,
	}
}

// NewTCMessageEndComponentsElemBoundReturnResultNotLast creates a TCMessageEndComponentsElemBound with the returnResultNotLast alternative.
func NewTCMessageEndComponentsElemBoundReturnResultNotLast(v ReturnResult) TCMessageEndComponentsElemBound {
	return TCMessageEndComponentsElemBound{
		Choice:              TCMessageEndComponentsElemBoundChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// TCMessageEndComponentsBound represents the ASN.1 type TCMessage-end-components-Bound (SEQUENCE_OF).
type TCMessageEndComponentsBound struct {
	Values       []TCMessageEndComponentsElemBound `json:"Values"`
	berOriginal_ []byte                            `json:"-"`
	berSnapshot_ []byte                            `json:"-"`
}

// TCMessageEndBound represents the ASN.1 type TCMessage-end-Bound (SEQUENCE).
type TCMessageEndBound struct {
	Dtid             DestTransactionID            `asn1:""`
	DialoguePortion  *DialoguePortion             `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *TCMessageEndComponentsBound `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool                         `asn1:"-" json:"-"`
	berOriginal_     []byte                       `asn1:"-" json:"-"`
	berSnapshot_     []byte                       `asn1:"-" json:"-"`
}

// TCMessageContinueComponentsElemBasicROSInvokeBound represents the ASN.1 type TCMessage-continue-components-Elem-basicROS-invoke-Bound (SEQUENCE).
type TCMessageContinueComponentsElemBasicROSInvokeBound struct {
	InvokeId     TCInvokeIdSet                                               `asn1:""`
	LinkedId     *TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode       Code                                                        `asn1:""`
	Argument     *runtime.RawValue                                           `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                                                      `asn1:"-" json:"-"`
	berSnapshot_ []byte                                                      `asn1:"-" json:"-"`
}

// TCMessageContinueComponentsElemBasicROSBound choice constants.
const (
	TCMessageContinueComponentsElemBasicROSBoundChoiceInvoke       = 1
	TCMessageContinueComponentsElemBasicROSBoundChoiceReturnResult = 2
	TCMessageContinueComponentsElemBasicROSBoundChoiceReturnError  = 3
	TCMessageContinueComponentsElemBasicROSBoundChoiceReject       = 4
)

// TCMessageContinueComponentsElemBasicROSBound represents the ASN.1 CHOICE type TCMessage-continue-components-Elem-basicROS-Bound.
type TCMessageContinueComponentsElemBasicROSBound struct {
	Choice       int
	berOriginal_ []byte                                              `json:"-"`
	berSnapshot_ []byte                                              `json:"-"`
	Invoke       *TCMessageContinueComponentsElemBasicROSInvokeBound `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult                                       `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError                                        `json:"ReturnError,omitempty"`
	Reject       *Reject                                             `json:"Reject,omitempty"`
}

// NewTCMessageContinueComponentsElemBasicROSBoundInvoke creates a TCMessageContinueComponentsElemBasicROSBound with the invoke alternative.
func NewTCMessageContinueComponentsElemBasicROSBoundInvoke(v TCMessageContinueComponentsElemBasicROSInvokeBound) TCMessageContinueComponentsElemBasicROSBound {
	return TCMessageContinueComponentsElemBasicROSBound{
		Choice: TCMessageContinueComponentsElemBasicROSBoundChoiceInvoke,
		Invoke: &v,
	}
}

// NewTCMessageContinueComponentsElemBasicROSBoundReturnResult creates a TCMessageContinueComponentsElemBasicROSBound with the returnResult alternative.
func NewTCMessageContinueComponentsElemBasicROSBoundReturnResult(v ReturnResult) TCMessageContinueComponentsElemBasicROSBound {
	return TCMessageContinueComponentsElemBasicROSBound{
		Choice:       TCMessageContinueComponentsElemBasicROSBoundChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewTCMessageContinueComponentsElemBasicROSBoundReturnError creates a TCMessageContinueComponentsElemBasicROSBound with the returnError alternative.
func NewTCMessageContinueComponentsElemBasicROSBoundReturnError(v ReturnError) TCMessageContinueComponentsElemBasicROSBound {
	return TCMessageContinueComponentsElemBasicROSBound{
		Choice:      TCMessageContinueComponentsElemBasicROSBoundChoiceReturnError,
		ReturnError: &v,
	}
}

// NewTCMessageContinueComponentsElemBasicROSBoundReject creates a TCMessageContinueComponentsElemBasicROSBound with the reject alternative.
func NewTCMessageContinueComponentsElemBasicROSBoundReject(v Reject) TCMessageContinueComponentsElemBasicROSBound {
	return TCMessageContinueComponentsElemBasicROSBound{
		Choice: TCMessageContinueComponentsElemBasicROSBoundChoiceReject,
		Reject: &v,
	}
}

// TCMessageContinueComponentsElemBound choice constants.
const (
	TCMessageContinueComponentsElemBoundChoiceBasicROS            = 1
	TCMessageContinueComponentsElemBoundChoiceReturnResultNotLast = 2
)

// TCMessageContinueComponentsElemBound represents the ASN.1 CHOICE type TCMessage-continue-components-Elem-Bound.
type TCMessageContinueComponentsElemBound struct {
	Choice              int
	berOriginal_        []byte                                        `json:"-"`
	berSnapshot_        []byte                                        `json:"-"`
	BasicROS            *TCMessageContinueComponentsElemBasicROSBound `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult                                 `json:"ReturnResultNotLast,omitempty"`
}

// NewTCMessageContinueComponentsElemBoundBasicROS creates a TCMessageContinueComponentsElemBound with the basicROS alternative.
func NewTCMessageContinueComponentsElemBoundBasicROS(v TCMessageContinueComponentsElemBasicROSBound) TCMessageContinueComponentsElemBound {
	return TCMessageContinueComponentsElemBound{
		Choice:   TCMessageContinueComponentsElemBoundChoiceBasicROS,
		BasicROS: &v,
	}
}

// NewTCMessageContinueComponentsElemBoundReturnResultNotLast creates a TCMessageContinueComponentsElemBound with the returnResultNotLast alternative.
func NewTCMessageContinueComponentsElemBoundReturnResultNotLast(v ReturnResult) TCMessageContinueComponentsElemBound {
	return TCMessageContinueComponentsElemBound{
		Choice:              TCMessageContinueComponentsElemBoundChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// TCMessageContinueComponentsBound represents the ASN.1 type TCMessage-continue-components-Bound (SEQUENCE_OF).
type TCMessageContinueComponentsBound struct {
	Values       []TCMessageContinueComponentsElemBound `json:"Values"`
	berOriginal_ []byte                                 `json:"-"`
	berSnapshot_ []byte                                 `json:"-"`
}

// TCMessageContinueBound represents the ASN.1 type TCMessage-continue-Bound (SEQUENCE).
type TCMessageContinueBound struct {
	Otid             OrigTransactionID                 `asn1:""`
	Dtid             DestTransactionID                 `asn1:""`
	DialoguePortion  *DialoguePortion                  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *TCMessageContinueComponentsBound `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool                              `asn1:"-" json:"-"`
	berOriginal_     []byte                            `asn1:"-" json:"-"`
	berSnapshot_     []byte                            `asn1:"-" json:"-"`
}

// UnidirectionalComponentsElemBasicROSInvokeBound represents the ASN.1 type Unidirectional-components-Elem-basicROS-invoke-Bound (SEQUENCE).
type UnidirectionalComponentsElemBasicROSInvokeBound struct {
	InvokeId     TCInvokeIdSet                                            `asn1:""`
	LinkedId     *UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode       Code                                                     `asn1:""`
	Argument     *runtime.RawValue                                        `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                                                   `asn1:"-" json:"-"`
	berSnapshot_ []byte                                                   `asn1:"-" json:"-"`
}

// UnidirectionalComponentsElemBasicROSBound choice constants.
const (
	UnidirectionalComponentsElemBasicROSBoundChoiceInvoke       = 1
	UnidirectionalComponentsElemBasicROSBoundChoiceReturnResult = 2
	UnidirectionalComponentsElemBasicROSBoundChoiceReturnError  = 3
	UnidirectionalComponentsElemBasicROSBoundChoiceReject       = 4
)

// UnidirectionalComponentsElemBasicROSBound represents the ASN.1 CHOICE type Unidirectional-components-Elem-basicROS-Bound.
type UnidirectionalComponentsElemBasicROSBound struct {
	Choice       int
	berOriginal_ []byte                                           `json:"-"`
	berSnapshot_ []byte                                           `json:"-"`
	Invoke       *UnidirectionalComponentsElemBasicROSInvokeBound `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult                                    `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError                                     `json:"ReturnError,omitempty"`
	Reject       *Reject                                          `json:"Reject,omitempty"`
}

// NewUnidirectionalComponentsElemBasicROSBoundInvoke creates a UnidirectionalComponentsElemBasicROSBound with the invoke alternative.
func NewUnidirectionalComponentsElemBasicROSBoundInvoke(v UnidirectionalComponentsElemBasicROSInvokeBound) UnidirectionalComponentsElemBasicROSBound {
	return UnidirectionalComponentsElemBasicROSBound{
		Choice: UnidirectionalComponentsElemBasicROSBoundChoiceInvoke,
		Invoke: &v,
	}
}

// NewUnidirectionalComponentsElemBasicROSBoundReturnResult creates a UnidirectionalComponentsElemBasicROSBound with the returnResult alternative.
func NewUnidirectionalComponentsElemBasicROSBoundReturnResult(v ReturnResult) UnidirectionalComponentsElemBasicROSBound {
	return UnidirectionalComponentsElemBasicROSBound{
		Choice:       UnidirectionalComponentsElemBasicROSBoundChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewUnidirectionalComponentsElemBasicROSBoundReturnError creates a UnidirectionalComponentsElemBasicROSBound with the returnError alternative.
func NewUnidirectionalComponentsElemBasicROSBoundReturnError(v ReturnError) UnidirectionalComponentsElemBasicROSBound {
	return UnidirectionalComponentsElemBasicROSBound{
		Choice:      UnidirectionalComponentsElemBasicROSBoundChoiceReturnError,
		ReturnError: &v,
	}
}

// NewUnidirectionalComponentsElemBasicROSBoundReject creates a UnidirectionalComponentsElemBasicROSBound with the reject alternative.
func NewUnidirectionalComponentsElemBasicROSBoundReject(v Reject) UnidirectionalComponentsElemBasicROSBound {
	return UnidirectionalComponentsElemBasicROSBound{
		Choice: UnidirectionalComponentsElemBasicROSBoundChoiceReject,
		Reject: &v,
	}
}

// UnidirectionalComponentsElemBound choice constants.
const (
	UnidirectionalComponentsElemBoundChoiceBasicROS            = 1
	UnidirectionalComponentsElemBoundChoiceReturnResultNotLast = 2
)

// UnidirectionalComponentsElemBound represents the ASN.1 CHOICE type Unidirectional-components-Elem-Bound.
type UnidirectionalComponentsElemBound struct {
	Choice              int
	berOriginal_        []byte                                     `json:"-"`
	berSnapshot_        []byte                                     `json:"-"`
	BasicROS            *UnidirectionalComponentsElemBasicROSBound `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult                              `json:"ReturnResultNotLast,omitempty"`
}

// NewUnidirectionalComponentsElemBoundBasicROS creates a UnidirectionalComponentsElemBound with the basicROS alternative.
func NewUnidirectionalComponentsElemBoundBasicROS(v UnidirectionalComponentsElemBasicROSBound) UnidirectionalComponentsElemBound {
	return UnidirectionalComponentsElemBound{
		Choice:   UnidirectionalComponentsElemBoundChoiceBasicROS,
		BasicROS: &v,
	}
}

// NewUnidirectionalComponentsElemBoundReturnResultNotLast creates a UnidirectionalComponentsElemBound with the returnResultNotLast alternative.
func NewUnidirectionalComponentsElemBoundReturnResultNotLast(v ReturnResult) UnidirectionalComponentsElemBound {
	return UnidirectionalComponentsElemBound{
		Choice:              UnidirectionalComponentsElemBoundChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// UnidirectionalComponentsBound represents the ASN.1 type Unidirectional-components-Bound (SEQUENCE_OF).
type UnidirectionalComponentsBound struct {
	Values       []UnidirectionalComponentsElemBound `json:"Values"`
	berOriginal_ []byte                              `json:"-"`
	berSnapshot_ []byte                              `json:"-"`
}

// BeginComponentsElemBasicROSInvokeBound represents the ASN.1 type Begin-components-Elem-basicROS-invoke-Bound (SEQUENCE).
type BeginComponentsElemBasicROSInvokeBound struct {
	InvokeId     TCInvokeIdSet                                   `asn1:""`
	LinkedId     *BeginComponentsElemBasicROSInvokeBoundLinkedId `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode       Code                                            `asn1:""`
	Argument     *runtime.RawValue                               `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                                          `asn1:"-" json:"-"`
	berSnapshot_ []byte                                          `asn1:"-" json:"-"`
}

// BeginComponentsElemBasicROSBound choice constants.
const (
	BeginComponentsElemBasicROSBoundChoiceInvoke       = 1
	BeginComponentsElemBasicROSBoundChoiceReturnResult = 2
	BeginComponentsElemBasicROSBoundChoiceReturnError  = 3
	BeginComponentsElemBasicROSBoundChoiceReject       = 4
)

// BeginComponentsElemBasicROSBound represents the ASN.1 CHOICE type Begin-components-Elem-basicROS-Bound.
type BeginComponentsElemBasicROSBound struct {
	Choice       int
	berOriginal_ []byte                                  `json:"-"`
	berSnapshot_ []byte                                  `json:"-"`
	Invoke       *BeginComponentsElemBasicROSInvokeBound `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult                           `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError                            `json:"ReturnError,omitempty"`
	Reject       *Reject                                 `json:"Reject,omitempty"`
}

// NewBeginComponentsElemBasicROSBoundInvoke creates a BeginComponentsElemBasicROSBound with the invoke alternative.
func NewBeginComponentsElemBasicROSBoundInvoke(v BeginComponentsElemBasicROSInvokeBound) BeginComponentsElemBasicROSBound {
	return BeginComponentsElemBasicROSBound{
		Choice: BeginComponentsElemBasicROSBoundChoiceInvoke,
		Invoke: &v,
	}
}

// NewBeginComponentsElemBasicROSBoundReturnResult creates a BeginComponentsElemBasicROSBound with the returnResult alternative.
func NewBeginComponentsElemBasicROSBoundReturnResult(v ReturnResult) BeginComponentsElemBasicROSBound {
	return BeginComponentsElemBasicROSBound{
		Choice:       BeginComponentsElemBasicROSBoundChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewBeginComponentsElemBasicROSBoundReturnError creates a BeginComponentsElemBasicROSBound with the returnError alternative.
func NewBeginComponentsElemBasicROSBoundReturnError(v ReturnError) BeginComponentsElemBasicROSBound {
	return BeginComponentsElemBasicROSBound{
		Choice:      BeginComponentsElemBasicROSBoundChoiceReturnError,
		ReturnError: &v,
	}
}

// NewBeginComponentsElemBasicROSBoundReject creates a BeginComponentsElemBasicROSBound with the reject alternative.
func NewBeginComponentsElemBasicROSBoundReject(v Reject) BeginComponentsElemBasicROSBound {
	return BeginComponentsElemBasicROSBound{
		Choice: BeginComponentsElemBasicROSBoundChoiceReject,
		Reject: &v,
	}
}

// BeginComponentsElemBound choice constants.
const (
	BeginComponentsElemBoundChoiceBasicROS            = 1
	BeginComponentsElemBoundChoiceReturnResultNotLast = 2
)

// BeginComponentsElemBound represents the ASN.1 CHOICE type Begin-components-Elem-Bound.
type BeginComponentsElemBound struct {
	Choice              int
	berOriginal_        []byte                            `json:"-"`
	berSnapshot_        []byte                            `json:"-"`
	BasicROS            *BeginComponentsElemBasicROSBound `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult                     `json:"ReturnResultNotLast,omitempty"`
}

// NewBeginComponentsElemBoundBasicROS creates a BeginComponentsElemBound with the basicROS alternative.
func NewBeginComponentsElemBoundBasicROS(v BeginComponentsElemBasicROSBound) BeginComponentsElemBound {
	return BeginComponentsElemBound{
		Choice:   BeginComponentsElemBoundChoiceBasicROS,
		BasicROS: &v,
	}
}

// NewBeginComponentsElemBoundReturnResultNotLast creates a BeginComponentsElemBound with the returnResultNotLast alternative.
func NewBeginComponentsElemBoundReturnResultNotLast(v ReturnResult) BeginComponentsElemBound {
	return BeginComponentsElemBound{
		Choice:              BeginComponentsElemBoundChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// BeginComponentsBound represents the ASN.1 type Begin-components-Bound (SEQUENCE_OF).
type BeginComponentsBound struct {
	Values       []BeginComponentsElemBound `json:"Values"`
	berOriginal_ []byte                     `json:"-"`
	berSnapshot_ []byte                     `json:"-"`
}

// EndComponentsElemBasicROSInvokeBound represents the ASN.1 type End-components-Elem-basicROS-invoke-Bound (SEQUENCE).
type EndComponentsElemBasicROSInvokeBound struct {
	InvokeId     TCInvokeIdSet                                 `asn1:""`
	LinkedId     *EndComponentsElemBasicROSInvokeBoundLinkedId `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode       Code                                          `asn1:""`
	Argument     *runtime.RawValue                             `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                                        `asn1:"-" json:"-"`
	berSnapshot_ []byte                                        `asn1:"-" json:"-"`
}

// EndComponentsElemBasicROSBound choice constants.
const (
	EndComponentsElemBasicROSBoundChoiceInvoke       = 1
	EndComponentsElemBasicROSBoundChoiceReturnResult = 2
	EndComponentsElemBasicROSBoundChoiceReturnError  = 3
	EndComponentsElemBasicROSBoundChoiceReject       = 4
)

// EndComponentsElemBasicROSBound represents the ASN.1 CHOICE type End-components-Elem-basicROS-Bound.
type EndComponentsElemBasicROSBound struct {
	Choice       int
	berOriginal_ []byte                                `json:"-"`
	berSnapshot_ []byte                                `json:"-"`
	Invoke       *EndComponentsElemBasicROSInvokeBound `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult                         `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError                          `json:"ReturnError,omitempty"`
	Reject       *Reject                               `json:"Reject,omitempty"`
}

// NewEndComponentsElemBasicROSBoundInvoke creates a EndComponentsElemBasicROSBound with the invoke alternative.
func NewEndComponentsElemBasicROSBoundInvoke(v EndComponentsElemBasicROSInvokeBound) EndComponentsElemBasicROSBound {
	return EndComponentsElemBasicROSBound{
		Choice: EndComponentsElemBasicROSBoundChoiceInvoke,
		Invoke: &v,
	}
}

// NewEndComponentsElemBasicROSBoundReturnResult creates a EndComponentsElemBasicROSBound with the returnResult alternative.
func NewEndComponentsElemBasicROSBoundReturnResult(v ReturnResult) EndComponentsElemBasicROSBound {
	return EndComponentsElemBasicROSBound{
		Choice:       EndComponentsElemBasicROSBoundChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewEndComponentsElemBasicROSBoundReturnError creates a EndComponentsElemBasicROSBound with the returnError alternative.
func NewEndComponentsElemBasicROSBoundReturnError(v ReturnError) EndComponentsElemBasicROSBound {
	return EndComponentsElemBasicROSBound{
		Choice:      EndComponentsElemBasicROSBoundChoiceReturnError,
		ReturnError: &v,
	}
}

// NewEndComponentsElemBasicROSBoundReject creates a EndComponentsElemBasicROSBound with the reject alternative.
func NewEndComponentsElemBasicROSBoundReject(v Reject) EndComponentsElemBasicROSBound {
	return EndComponentsElemBasicROSBound{
		Choice: EndComponentsElemBasicROSBoundChoiceReject,
		Reject: &v,
	}
}

// EndComponentsElemBound choice constants.
const (
	EndComponentsElemBoundChoiceBasicROS            = 1
	EndComponentsElemBoundChoiceReturnResultNotLast = 2
)

// EndComponentsElemBound represents the ASN.1 CHOICE type End-components-Elem-Bound.
type EndComponentsElemBound struct {
	Choice              int
	berOriginal_        []byte                          `json:"-"`
	berSnapshot_        []byte                          `json:"-"`
	BasicROS            *EndComponentsElemBasicROSBound `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult                   `json:"ReturnResultNotLast,omitempty"`
}

// NewEndComponentsElemBoundBasicROS creates a EndComponentsElemBound with the basicROS alternative.
func NewEndComponentsElemBoundBasicROS(v EndComponentsElemBasicROSBound) EndComponentsElemBound {
	return EndComponentsElemBound{
		Choice:   EndComponentsElemBoundChoiceBasicROS,
		BasicROS: &v,
	}
}

// NewEndComponentsElemBoundReturnResultNotLast creates a EndComponentsElemBound with the returnResultNotLast alternative.
func NewEndComponentsElemBoundReturnResultNotLast(v ReturnResult) EndComponentsElemBound {
	return EndComponentsElemBound{
		Choice:              EndComponentsElemBoundChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// EndComponentsBound represents the ASN.1 type End-components-Bound (SEQUENCE_OF).
type EndComponentsBound struct {
	Values       []EndComponentsElemBound `json:"Values"`
	berOriginal_ []byte                   `json:"-"`
	berSnapshot_ []byte                   `json:"-"`
}

// ContinueComponentsElemBasicROSInvokeBound represents the ASN.1 type Continue-components-Elem-basicROS-invoke-Bound (SEQUENCE).
type ContinueComponentsElemBasicROSInvokeBound struct {
	InvokeId     TCInvokeIdSet                                      `asn1:""`
	LinkedId     *ContinueComponentsElemBasicROSInvokeBoundLinkedId `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode       Code                                               `asn1:""`
	Argument     *runtime.RawValue                                  `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                                             `asn1:"-" json:"-"`
	berSnapshot_ []byte                                             `asn1:"-" json:"-"`
}

// ContinueComponentsElemBasicROSBound choice constants.
const (
	ContinueComponentsElemBasicROSBoundChoiceInvoke       = 1
	ContinueComponentsElemBasicROSBoundChoiceReturnResult = 2
	ContinueComponentsElemBasicROSBoundChoiceReturnError  = 3
	ContinueComponentsElemBasicROSBoundChoiceReject       = 4
)

// ContinueComponentsElemBasicROSBound represents the ASN.1 CHOICE type Continue-components-Elem-basicROS-Bound.
type ContinueComponentsElemBasicROSBound struct {
	Choice       int
	berOriginal_ []byte                                     `json:"-"`
	berSnapshot_ []byte                                     `json:"-"`
	Invoke       *ContinueComponentsElemBasicROSInvokeBound `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult                              `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError                               `json:"ReturnError,omitempty"`
	Reject       *Reject                                    `json:"Reject,omitempty"`
}

// NewContinueComponentsElemBasicROSBoundInvoke creates a ContinueComponentsElemBasicROSBound with the invoke alternative.
func NewContinueComponentsElemBasicROSBoundInvoke(v ContinueComponentsElemBasicROSInvokeBound) ContinueComponentsElemBasicROSBound {
	return ContinueComponentsElemBasicROSBound{
		Choice: ContinueComponentsElemBasicROSBoundChoiceInvoke,
		Invoke: &v,
	}
}

// NewContinueComponentsElemBasicROSBoundReturnResult creates a ContinueComponentsElemBasicROSBound with the returnResult alternative.
func NewContinueComponentsElemBasicROSBoundReturnResult(v ReturnResult) ContinueComponentsElemBasicROSBound {
	return ContinueComponentsElemBasicROSBound{
		Choice:       ContinueComponentsElemBasicROSBoundChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewContinueComponentsElemBasicROSBoundReturnError creates a ContinueComponentsElemBasicROSBound with the returnError alternative.
func NewContinueComponentsElemBasicROSBoundReturnError(v ReturnError) ContinueComponentsElemBasicROSBound {
	return ContinueComponentsElemBasicROSBound{
		Choice:      ContinueComponentsElemBasicROSBoundChoiceReturnError,
		ReturnError: &v,
	}
}

// NewContinueComponentsElemBasicROSBoundReject creates a ContinueComponentsElemBasicROSBound with the reject alternative.
func NewContinueComponentsElemBasicROSBoundReject(v Reject) ContinueComponentsElemBasicROSBound {
	return ContinueComponentsElemBasicROSBound{
		Choice: ContinueComponentsElemBasicROSBoundChoiceReject,
		Reject: &v,
	}
}

// ContinueComponentsElemBound choice constants.
const (
	ContinueComponentsElemBoundChoiceBasicROS            = 1
	ContinueComponentsElemBoundChoiceReturnResultNotLast = 2
)

// ContinueComponentsElemBound represents the ASN.1 CHOICE type Continue-components-Elem-Bound.
type ContinueComponentsElemBound struct {
	Choice              int
	berOriginal_        []byte                               `json:"-"`
	berSnapshot_        []byte                               `json:"-"`
	BasicROS            *ContinueComponentsElemBasicROSBound `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult                        `json:"ReturnResultNotLast,omitempty"`
}

// NewContinueComponentsElemBoundBasicROS creates a ContinueComponentsElemBound with the basicROS alternative.
func NewContinueComponentsElemBoundBasicROS(v ContinueComponentsElemBasicROSBound) ContinueComponentsElemBound {
	return ContinueComponentsElemBound{
		Choice:   ContinueComponentsElemBoundChoiceBasicROS,
		BasicROS: &v,
	}
}

// NewContinueComponentsElemBoundReturnResultNotLast creates a ContinueComponentsElemBound with the returnResultNotLast alternative.
func NewContinueComponentsElemBoundReturnResultNotLast(v ReturnResult) ContinueComponentsElemBound {
	return ContinueComponentsElemBound{
		Choice:              ContinueComponentsElemBoundChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// ContinueComponentsBound represents the ASN.1 type Continue-components-Bound (SEQUENCE_OF).
type ContinueComponentsBound struct {
	Values       []ContinueComponentsElemBound `json:"Values"`
	berOriginal_ []byte                        `json:"-"`
	berSnapshot_ []byte                        `json:"-"`
}

// ComponentPortionElemBasicROSInvokeBound represents the ASN.1 type ComponentPortion-Elem-basicROS-invoke-Bound (SEQUENCE).
type ComponentPortionElemBasicROSInvokeBound struct {
	InvokeId     TCInvokeIdSet                                    `asn1:""`
	LinkedId     *ComponentPortionElemBasicROSInvokeBoundLinkedId `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode       Code                                             `asn1:""`
	Argument     *runtime.RawValue                                `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                                           `asn1:"-" json:"-"`
	berSnapshot_ []byte                                           `asn1:"-" json:"-"`
}

// ComponentPortionElemBasicROSBound choice constants.
const (
	ComponentPortionElemBasicROSBoundChoiceInvoke       = 1
	ComponentPortionElemBasicROSBoundChoiceReturnResult = 2
	ComponentPortionElemBasicROSBoundChoiceReturnError  = 3
	ComponentPortionElemBasicROSBoundChoiceReject       = 4
)

// ComponentPortionElemBasicROSBound represents the ASN.1 CHOICE type ComponentPortion-Elem-basicROS-Bound.
type ComponentPortionElemBasicROSBound struct {
	Choice       int
	berOriginal_ []byte                                   `json:"-"`
	berSnapshot_ []byte                                   `json:"-"`
	Invoke       *ComponentPortionElemBasicROSInvokeBound `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult                            `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError                             `json:"ReturnError,omitempty"`
	Reject       *Reject                                  `json:"Reject,omitempty"`
}

// NewComponentPortionElemBasicROSBoundInvoke creates a ComponentPortionElemBasicROSBound with the invoke alternative.
func NewComponentPortionElemBasicROSBoundInvoke(v ComponentPortionElemBasicROSInvokeBound) ComponentPortionElemBasicROSBound {
	return ComponentPortionElemBasicROSBound{
		Choice: ComponentPortionElemBasicROSBoundChoiceInvoke,
		Invoke: &v,
	}
}

// NewComponentPortionElemBasicROSBoundReturnResult creates a ComponentPortionElemBasicROSBound with the returnResult alternative.
func NewComponentPortionElemBasicROSBoundReturnResult(v ReturnResult) ComponentPortionElemBasicROSBound {
	return ComponentPortionElemBasicROSBound{
		Choice:       ComponentPortionElemBasicROSBoundChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewComponentPortionElemBasicROSBoundReturnError creates a ComponentPortionElemBasicROSBound with the returnError alternative.
func NewComponentPortionElemBasicROSBoundReturnError(v ReturnError) ComponentPortionElemBasicROSBound {
	return ComponentPortionElemBasicROSBound{
		Choice:      ComponentPortionElemBasicROSBoundChoiceReturnError,
		ReturnError: &v,
	}
}

// NewComponentPortionElemBasicROSBoundReject creates a ComponentPortionElemBasicROSBound with the reject alternative.
func NewComponentPortionElemBasicROSBoundReject(v Reject) ComponentPortionElemBasicROSBound {
	return ComponentPortionElemBasicROSBound{
		Choice: ComponentPortionElemBasicROSBoundChoiceReject,
		Reject: &v,
	}
}

// ComponentPortionElemBound choice constants.
const (
	ComponentPortionElemBoundChoiceBasicROS            = 1
	ComponentPortionElemBoundChoiceReturnResultNotLast = 2
)

// ComponentPortionElemBound represents the ASN.1 CHOICE type ComponentPortion-Elem-Bound.
type ComponentPortionElemBound struct {
	Choice              int
	berOriginal_        []byte                             `json:"-"`
	berSnapshot_        []byte                             `json:"-"`
	BasicROS            *ComponentPortionElemBasicROSBound `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult                      `json:"ReturnResultNotLast,omitempty"`
}

// NewComponentPortionElemBoundBasicROS creates a ComponentPortionElemBound with the basicROS alternative.
func NewComponentPortionElemBoundBasicROS(v ComponentPortionElemBasicROSBound) ComponentPortionElemBound {
	return ComponentPortionElemBound{
		Choice:   ComponentPortionElemBoundChoiceBasicROS,
		BasicROS: &v,
	}
}

// NewComponentPortionElemBoundReturnResultNotLast creates a ComponentPortionElemBound with the returnResultNotLast alternative.
func NewComponentPortionElemBoundReturnResultNotLast(v ReturnResult) ComponentPortionElemBound {
	return ComponentPortionElemBound{
		Choice:              ComponentPortionElemBoundChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// ComponentBasicROSInvokeBound represents the ASN.1 type Component-basicROS-invoke-Bound (SEQUENCE).
type ComponentBasicROSInvokeBound struct {
	InvokeId     TCInvokeIdSet                         `asn1:""`
	LinkedId     *ComponentBasicROSInvokeBoundLinkedId `asn1:",optional" json:"LinkedId,omitempty"`
	Opcode       Code                                  `asn1:""`
	Argument     *runtime.RawValue                     `asn1:",optional" json:"Argument,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                                `asn1:"-" json:"-"`
	berSnapshot_ []byte                                `asn1:"-" json:"-"`
}

// ComponentBasicROSBound choice constants.
const (
	ComponentBasicROSBoundChoiceInvoke       = 1
	ComponentBasicROSBoundChoiceReturnResult = 2
	ComponentBasicROSBoundChoiceReturnError  = 3
	ComponentBasicROSBoundChoiceReject       = 4
)

// ComponentBasicROSBound represents the ASN.1 CHOICE type Component-basicROS-Bound.
type ComponentBasicROSBound struct {
	Choice       int
	berOriginal_ []byte                        `json:"-"`
	berSnapshot_ []byte                        `json:"-"`
	Invoke       *ComponentBasicROSInvokeBound `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult                 `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError                  `json:"ReturnError,omitempty"`
	Reject       *Reject                       `json:"Reject,omitempty"`
}

// NewComponentBasicROSBoundInvoke creates a ComponentBasicROSBound with the invoke alternative.
func NewComponentBasicROSBoundInvoke(v ComponentBasicROSInvokeBound) ComponentBasicROSBound {
	return ComponentBasicROSBound{
		Choice: ComponentBasicROSBoundChoiceInvoke,
		Invoke: &v,
	}
}

// NewComponentBasicROSBoundReturnResult creates a ComponentBasicROSBound with the returnResult alternative.
func NewComponentBasicROSBoundReturnResult(v ReturnResult) ComponentBasicROSBound {
	return ComponentBasicROSBound{
		Choice:       ComponentBasicROSBoundChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewComponentBasicROSBoundReturnError creates a ComponentBasicROSBound with the returnError alternative.
func NewComponentBasicROSBoundReturnError(v ReturnError) ComponentBasicROSBound {
	return ComponentBasicROSBound{
		Choice:      ComponentBasicROSBoundChoiceReturnError,
		ReturnError: &v,
	}
}

// NewComponentBasicROSBoundReject creates a ComponentBasicROSBound with the reject alternative.
func NewComponentBasicROSBoundReject(v Reject) ComponentBasicROSBound {
	return ComponentBasicROSBound{
		Choice: ComponentBasicROSBoundChoiceReject,
		Reject: &v,
	}
}

// AbortReason choice constants.
const (
	AbortReasonChoicePAbortCause = 1
	AbortReasonChoiceUAbortCause = 2
)

// AbortReason represents the ASN.1 CHOICE type Abort-reason.
type AbortReason struct {
	Choice       int
	berOriginal_ []byte           `json:"-"`
	berSnapshot_ []byte           `json:"-"`
	PAbortCause  *PAbortCause     `json:"PAbortCause,omitempty"`
	UAbortCause  *DialoguePortion `json:"UAbortCause,omitempty"`
}

// NewAbortReasonPAbortCause creates a AbortReason with the p-abortCause alternative.
func NewAbortReasonPAbortCause(v PAbortCause) AbortReason {
	return AbortReason{
		Choice:      AbortReasonChoicePAbortCause,
		PAbortCause: &v,
	}
}

// NewAbortReasonUAbortCause creates a AbortReason with the u-abortCause alternative.
func NewAbortReasonUAbortCause(v DialoguePortion) AbortReason {
	return AbortReason{
		Choice:      AbortReasonChoiceUAbortCause,
		UAbortCause: &v,
	}
}

// ComponentReturnResultNotLastResult represents the ASN.1 type Component-returnResultNotLast-result (SEQUENCE).
type ComponentReturnResultNotLastResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId choice constants.
const (
	TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent = 1
	TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent  = 2
)

// TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId represents the ASN.1 CHOICE type TCMessage-unidirectional-components-Elem-basicROS-invoke-Bound-linkedId.
type TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *big.Int  `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewTCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdPresent creates a TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId with the present alternative.
func NewTCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdPresent(v *big.Int) TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId {
	return TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId{
		Choice:  TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent,
		Present: v,
	}
}

// NewTCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdAbsent creates a TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId with the absent alternative.
func NewTCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdAbsent(v struct{}) TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId {
	return TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId{
		Choice: TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult represents the ASN.1 type TCMessage-unidirectional-components-Elem-basicROS-Bound-returnResult-result (SEQUENCE).
type TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult represents the ASN.1 type TCMessage-unidirectional-components-Elem-Bound-returnResultNotLast-result (SEQUENCE).
type TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId choice constants.
const (
	TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent = 1
	TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent  = 2
)

// TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId represents the ASN.1 CHOICE type TCMessage-begin-components-Elem-basicROS-invoke-Bound-linkedId.
type TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *big.Int  `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewTCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdPresent creates a TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId with the present alternative.
func NewTCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdPresent(v *big.Int) TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId {
	return TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId{
		Choice:  TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent,
		Present: v,
	}
}

// NewTCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdAbsent creates a TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId with the absent alternative.
func NewTCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdAbsent(v struct{}) TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId {
	return TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId{
		Choice: TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// TCMessageBeginComponentsElemBasicROSBoundReturnResultResult represents the ASN.1 type TCMessage-begin-components-Elem-basicROS-Bound-returnResult-result (SEQUENCE).
type TCMessageBeginComponentsElemBasicROSBoundReturnResultResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// TCMessageBeginComponentsElemBoundReturnResultNotLastResult represents the ASN.1 type TCMessage-begin-components-Elem-Bound-returnResultNotLast-result (SEQUENCE).
type TCMessageBeginComponentsElemBoundReturnResultNotLastResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId choice constants.
const (
	TCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent = 1
	TCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent  = 2
)

// TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId represents the ASN.1 CHOICE type TCMessage-end-components-Elem-basicROS-invoke-Bound-linkedId.
type TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *big.Int  `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewTCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdPresent creates a TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId with the present alternative.
func NewTCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdPresent(v *big.Int) TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId {
	return TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId{
		Choice:  TCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent,
		Present: v,
	}
}

// NewTCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdAbsent creates a TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId with the absent alternative.
func NewTCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdAbsent(v struct{}) TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId {
	return TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId{
		Choice: TCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// TCMessageEndComponentsElemBasicROSBoundReturnResultResult represents the ASN.1 type TCMessage-end-components-Elem-basicROS-Bound-returnResult-result (SEQUENCE).
type TCMessageEndComponentsElemBasicROSBoundReturnResultResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// TCMessageEndComponentsElemBoundReturnResultNotLastResult represents the ASN.1 type TCMessage-end-components-Elem-Bound-returnResultNotLast-result (SEQUENCE).
type TCMessageEndComponentsElemBoundReturnResultNotLastResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId choice constants.
const (
	TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent = 1
	TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent  = 2
)

// TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId represents the ASN.1 CHOICE type TCMessage-continue-components-Elem-basicROS-invoke-Bound-linkedId.
type TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *big.Int  `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewTCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdPresent creates a TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId with the present alternative.
func NewTCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdPresent(v *big.Int) TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId {
	return TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId{
		Choice:  TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent,
		Present: v,
	}
}

// NewTCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdAbsent creates a TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId with the absent alternative.
func NewTCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdAbsent(v struct{}) TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId {
	return TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId{
		Choice: TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// TCMessageContinueComponentsElemBasicROSBoundReturnResultResult represents the ASN.1 type TCMessage-continue-components-Elem-basicROS-Bound-returnResult-result (SEQUENCE).
type TCMessageContinueComponentsElemBasicROSBoundReturnResultResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// TCMessageContinueComponentsElemBoundReturnResultNotLastResult represents the ASN.1 type TCMessage-continue-components-Elem-Bound-returnResultNotLast-result (SEQUENCE).
type TCMessageContinueComponentsElemBoundReturnResultNotLastResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId choice constants.
const (
	UnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent = 1
	UnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent  = 2
)

// UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId represents the ASN.1 CHOICE type Unidirectional-components-Elem-basicROS-invoke-Bound-linkedId.
type UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *big.Int  `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdPresent creates a UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId with the present alternative.
func NewUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdPresent(v *big.Int) UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId {
	return UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId{
		Choice:  UnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent,
		Present: v,
	}
}

// NewUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdAbsent creates a UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId with the absent alternative.
func NewUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdAbsent(v struct{}) UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId {
	return UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId{
		Choice: UnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// UnidirectionalComponentsElemBasicROSBoundReturnResultResult represents the ASN.1 type Unidirectional-components-Elem-basicROS-Bound-returnResult-result (SEQUENCE).
type UnidirectionalComponentsElemBasicROSBoundReturnResultResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// UnidirectionalComponentsElemBoundReturnResultNotLastResult represents the ASN.1 type Unidirectional-components-Elem-Bound-returnResultNotLast-result (SEQUENCE).
type UnidirectionalComponentsElemBoundReturnResultNotLastResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// BeginComponentsElemBasicROSInvokeBoundLinkedId choice constants.
const (
	BeginComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent = 1
	BeginComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent  = 2
)

// BeginComponentsElemBasicROSInvokeBoundLinkedId represents the ASN.1 CHOICE type Begin-components-Elem-basicROS-invoke-Bound-linkedId.
type BeginComponentsElemBasicROSInvokeBoundLinkedId struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *big.Int  `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewBeginComponentsElemBasicROSInvokeBoundLinkedIdPresent creates a BeginComponentsElemBasicROSInvokeBoundLinkedId with the present alternative.
func NewBeginComponentsElemBasicROSInvokeBoundLinkedIdPresent(v *big.Int) BeginComponentsElemBasicROSInvokeBoundLinkedId {
	return BeginComponentsElemBasicROSInvokeBoundLinkedId{
		Choice:  BeginComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent,
		Present: v,
	}
}

// NewBeginComponentsElemBasicROSInvokeBoundLinkedIdAbsent creates a BeginComponentsElemBasicROSInvokeBoundLinkedId with the absent alternative.
func NewBeginComponentsElemBasicROSInvokeBoundLinkedIdAbsent(v struct{}) BeginComponentsElemBasicROSInvokeBoundLinkedId {
	return BeginComponentsElemBasicROSInvokeBoundLinkedId{
		Choice: BeginComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// BeginComponentsElemBasicROSBoundReturnResultResult represents the ASN.1 type Begin-components-Elem-basicROS-Bound-returnResult-result (SEQUENCE).
type BeginComponentsElemBasicROSBoundReturnResultResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// BeginComponentsElemBoundReturnResultNotLastResult represents the ASN.1 type Begin-components-Elem-Bound-returnResultNotLast-result (SEQUENCE).
type BeginComponentsElemBoundReturnResultNotLastResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// EndComponentsElemBasicROSInvokeBoundLinkedId choice constants.
const (
	EndComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent = 1
	EndComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent  = 2
)

// EndComponentsElemBasicROSInvokeBoundLinkedId represents the ASN.1 CHOICE type End-components-Elem-basicROS-invoke-Bound-linkedId.
type EndComponentsElemBasicROSInvokeBoundLinkedId struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *big.Int  `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewEndComponentsElemBasicROSInvokeBoundLinkedIdPresent creates a EndComponentsElemBasicROSInvokeBoundLinkedId with the present alternative.
func NewEndComponentsElemBasicROSInvokeBoundLinkedIdPresent(v *big.Int) EndComponentsElemBasicROSInvokeBoundLinkedId {
	return EndComponentsElemBasicROSInvokeBoundLinkedId{
		Choice:  EndComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent,
		Present: v,
	}
}

// NewEndComponentsElemBasicROSInvokeBoundLinkedIdAbsent creates a EndComponentsElemBasicROSInvokeBoundLinkedId with the absent alternative.
func NewEndComponentsElemBasicROSInvokeBoundLinkedIdAbsent(v struct{}) EndComponentsElemBasicROSInvokeBoundLinkedId {
	return EndComponentsElemBasicROSInvokeBoundLinkedId{
		Choice: EndComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// EndComponentsElemBasicROSBoundReturnResultResult represents the ASN.1 type End-components-Elem-basicROS-Bound-returnResult-result (SEQUENCE).
type EndComponentsElemBasicROSBoundReturnResultResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// EndComponentsElemBoundReturnResultNotLastResult represents the ASN.1 type End-components-Elem-Bound-returnResultNotLast-result (SEQUENCE).
type EndComponentsElemBoundReturnResultNotLastResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// ContinueComponentsElemBasicROSInvokeBoundLinkedId choice constants.
const (
	ContinueComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent = 1
	ContinueComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent  = 2
)

// ContinueComponentsElemBasicROSInvokeBoundLinkedId represents the ASN.1 CHOICE type Continue-components-Elem-basicROS-invoke-Bound-linkedId.
type ContinueComponentsElemBasicROSInvokeBoundLinkedId struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *big.Int  `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewContinueComponentsElemBasicROSInvokeBoundLinkedIdPresent creates a ContinueComponentsElemBasicROSInvokeBoundLinkedId with the present alternative.
func NewContinueComponentsElemBasicROSInvokeBoundLinkedIdPresent(v *big.Int) ContinueComponentsElemBasicROSInvokeBoundLinkedId {
	return ContinueComponentsElemBasicROSInvokeBoundLinkedId{
		Choice:  ContinueComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent,
		Present: v,
	}
}

// NewContinueComponentsElemBasicROSInvokeBoundLinkedIdAbsent creates a ContinueComponentsElemBasicROSInvokeBoundLinkedId with the absent alternative.
func NewContinueComponentsElemBasicROSInvokeBoundLinkedIdAbsent(v struct{}) ContinueComponentsElemBasicROSInvokeBoundLinkedId {
	return ContinueComponentsElemBasicROSInvokeBoundLinkedId{
		Choice: ContinueComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// ContinueComponentsElemBasicROSBoundReturnResultResult represents the ASN.1 type Continue-components-Elem-basicROS-Bound-returnResult-result (SEQUENCE).
type ContinueComponentsElemBasicROSBoundReturnResultResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// ContinueComponentsElemBoundReturnResultNotLastResult represents the ASN.1 type Continue-components-Elem-Bound-returnResultNotLast-result (SEQUENCE).
type ContinueComponentsElemBoundReturnResultNotLastResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// ComponentPortionElemBasicROSInvokeBoundLinkedId choice constants.
const (
	ComponentPortionElemBasicROSInvokeBoundLinkedIdChoicePresent = 1
	ComponentPortionElemBasicROSInvokeBoundLinkedIdChoiceAbsent  = 2
)

// ComponentPortionElemBasicROSInvokeBoundLinkedId represents the ASN.1 CHOICE type ComponentPortion-Elem-basicROS-invoke-Bound-linkedId.
type ComponentPortionElemBasicROSInvokeBoundLinkedId struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *big.Int  `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewComponentPortionElemBasicROSInvokeBoundLinkedIdPresent creates a ComponentPortionElemBasicROSInvokeBoundLinkedId with the present alternative.
func NewComponentPortionElemBasicROSInvokeBoundLinkedIdPresent(v *big.Int) ComponentPortionElemBasicROSInvokeBoundLinkedId {
	return ComponentPortionElemBasicROSInvokeBoundLinkedId{
		Choice:  ComponentPortionElemBasicROSInvokeBoundLinkedIdChoicePresent,
		Present: v,
	}
}

// NewComponentPortionElemBasicROSInvokeBoundLinkedIdAbsent creates a ComponentPortionElemBasicROSInvokeBoundLinkedId with the absent alternative.
func NewComponentPortionElemBasicROSInvokeBoundLinkedIdAbsent(v struct{}) ComponentPortionElemBasicROSInvokeBoundLinkedId {
	return ComponentPortionElemBasicROSInvokeBoundLinkedId{
		Choice: ComponentPortionElemBasicROSInvokeBoundLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// ComponentPortionElemBasicROSBoundReturnResultResult represents the ASN.1 type ComponentPortion-Elem-basicROS-Bound-returnResult-result (SEQUENCE).
type ComponentPortionElemBasicROSBoundReturnResultResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// ComponentPortionElemBoundReturnResultNotLastResult represents the ASN.1 type ComponentPortion-Elem-Bound-returnResultNotLast-result (SEQUENCE).
type ComponentPortionElemBoundReturnResultNotLastResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// ComponentBasicROSInvokeBoundLinkedId choice constants.
const (
	ComponentBasicROSInvokeBoundLinkedIdChoicePresent = 1
	ComponentBasicROSInvokeBoundLinkedIdChoiceAbsent  = 2
)

// ComponentBasicROSInvokeBoundLinkedId represents the ASN.1 CHOICE type Component-basicROS-invoke-Bound-linkedId.
type ComponentBasicROSInvokeBoundLinkedId struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *big.Int  `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewComponentBasicROSInvokeBoundLinkedIdPresent creates a ComponentBasicROSInvokeBoundLinkedId with the present alternative.
func NewComponentBasicROSInvokeBoundLinkedIdPresent(v *big.Int) ComponentBasicROSInvokeBoundLinkedId {
	return ComponentBasicROSInvokeBoundLinkedId{
		Choice:  ComponentBasicROSInvokeBoundLinkedIdChoicePresent,
		Present: v,
	}
}

// NewComponentBasicROSInvokeBoundLinkedIdAbsent creates a ComponentBasicROSInvokeBoundLinkedId with the absent alternative.
func NewComponentBasicROSInvokeBoundLinkedIdAbsent(v struct{}) ComponentBasicROSInvokeBoundLinkedId {
	return ComponentBasicROSInvokeBoundLinkedId{
		Choice: ComponentBasicROSInvokeBoundLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// ComponentBasicROSBoundReturnResultResult represents the ASN.1 type Component-basicROS-Bound-returnResult-result (SEQUENCE).
type ComponentBasicROSBoundReturnResultResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// MarshalBER encodes TCMessage to BER format.
func (v *TCMessage) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessage receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessage) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageChoiceUnidirectional:
		if v.Unidirectional == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: unidirectional is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Unidirectional.MarshalBER(ber.ChildEncodeOptions(opts, "unidirectional")...)
		if err != nil {
			return nil, qualifyBERError(err, "unidirectional", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "unidirectional", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case TCMessageChoiceBegin:
		if v.Begin == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: begin is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.Begin.MarshalBER(ber.ChildEncodeOptions(opts, "begin")...)
		if err != nil {
			return nil, qualifyBERError(err, "begin", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "begin", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case TCMessageChoiceEnd:
		if v.End == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: end is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.End.MarshalBER(ber.ChildEncodeOptions(opts, "end")...)
		if err != nil {
			return nil, qualifyBERError(err, "end", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 4, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "end", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case TCMessageChoiceContinue:
		if v.Continue == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: continue is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Continue.MarshalBER(ber.ChildEncodeOptions(opts, "continue")...)
		if err != nil {
			return nil, qualifyBERError(err, "continue", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 5, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "continue", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	case TCMessageChoiceAbort:
		if v.Abort == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: abort is nil", ber.ErrInvalidValue)
		}
		enc_4, err := v.Abort.MarshalBER(ber.ChildEncodeOptions(opts, "abort")...)
		if err != nil {
			return nil, qualifyBERError(err, "abort", "encoding", false)
		}
		retagged_enc_4, tagErr_enc_4 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 7, enc_4)
		if tagErr_enc_4 != nil {
			return nil, qualifyBERError(tagErr_enc_4, "abort", "encoding", false)
		}
		enc_4 = retagged_enc_4
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessage", v.Choice)
	}
}

// MarshalDER encodes TCMessage to DER format.
func (v *TCMessage) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessage receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case TCMessageChoiceUnidirectional:
		if v.Unidirectional == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: unidirectional is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Unidirectional.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "unidirectional", "encoding", true)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "unidirectional", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "unidirectional", "encoding", true)
		}
		return enc_der_0, nil
	case TCMessageChoiceBegin:
		if v.Begin == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: begin is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.Begin.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "begin", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "begin", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "begin", "encoding", true)
		}
		return enc_der_1, nil
	case TCMessageChoiceEnd:
		if v.End == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: end is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.End.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "end", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 4, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "end", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "end", "encoding", true)
		}
		return enc_der_2, nil
	case TCMessageChoiceContinue:
		if v.Continue == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: continue is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Continue.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "continue", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 5, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "continue", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "continue", "encoding", true)
		}
		return enc_der_3, nil
	case TCMessageChoiceAbort:
		if v.Abort == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: abort is nil", ber.ErrInvalidValue)
		}
		enc_der_4, err := v.Abort.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "abort", "encoding", true)
		}
		retagged_enc_der_4, tagErr_enc_der_4 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 7, enc_der_4)
		if tagErr_enc_der_4 != nil {
			return nil, qualifyBERError(tagErr_enc_der_4, "abort", "encoding", true)
		}
		enc_der_4 = retagged_enc_der_4
		if derErr := ber.ValidateDEREncodedElement(enc_der_4); derErr != nil {
			return nil, qualifyBERError(derErr, "abort", "encoding", true)
		}
		return enc_der_4, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageChoiceUnidirectional:
			return nil, qualifyBERError(err, "unidirectional", "encoding", true)
		case TCMessageChoiceBegin:
			return nil, qualifyBERError(err, "begin", "encoding", true)
		case TCMessageChoiceEnd:
			return nil, qualifyBERError(err, "end", "encoding", true)
		case TCMessageChoiceContinue:
			return nil, qualifyBERError(err, "continue", "encoding", true)
		case TCMessageChoiceAbort:
			return nil, qualifyBERError(err, "abort", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessage as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessage from BER/DER format.
func (v *TCMessage) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessage destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessage
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessage{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessage CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessage: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessage CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessage", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceUnidirectional
		ber.MarkPreflightTarget(opts, "unidirectional", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "unidirectional", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec TCMessageUnidirectionalBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "unidirectional")...); unmErr != nil {
			return qualifyBERError(unmErr, "unidirectional", "decoding", false)
		}
		v.Unidirectional = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceBegin
		ber.MarkPreflightTarget(opts, "begin", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "begin", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec TCMessageBeginBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "begin")...); unmErr != nil {
			return qualifyBERError(unmErr, "begin", "decoding", false)
		}
		v.Begin = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceEnd
		ber.MarkPreflightTarget(opts, "end", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "end", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec TCMessageEndBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "end")...); unmErr != nil {
			return qualifyBERError(unmErr, "end", "decoding", false)
		}
		v.End = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 5 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceContinue
		ber.MarkPreflightTarget(opts, "continue", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "continue", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec TCMessageContinueBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "continue")...); unmErr != nil {
			return qualifyBERError(unmErr, "continue", "decoding", false)
		}
		v.Continue = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceAbort
		ber.MarkPreflightTarget(opts, "abort", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "abort", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Abort
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "abort")...); unmErr != nil {
			return qualifyBERError(unmErr, "abort", "decoding", false)
		}
		v.Abort = &dec
	} else {
		return fmt.Errorf("unknown tag %s for TCMessage CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Unidirectional to BER format.
func (v *Unidirectional) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Unidirectional receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Unidirectional) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", false)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "components", "encoding", false)
	}
	if len((v.Components).Values) < 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_components, err := MarshalBERUnidirectionalComponentsBound(v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
	if err != nil {
		return nil, qualifyBERError(err, "components", "encoding", false)
	}
	if ber.BERReplayEnabled(opts) && v.ComponentsIndef_ {
		indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		{
			var encodeErr error
			enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "Components", "encoding", false)
			}
		}
	}
	children = append(children, enc_components...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes Unidirectional to DER format.
func (v *Unidirectional) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Unidirectional receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "components", "encoding", true)
	}
	if len((v.Components).Values) < 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_components, err := MarshalDERUnidirectionalComponentsBound(v.Components)
	if err != nil {
		return nil, qualifyBERError(err, "components", "encoding", true)
	}
	children = append(children, enc_components...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding Unidirectional as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes Unidirectional from BER/DER format.
func (v *Unidirectional) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Unidirectional destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Unidirectional
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = Unidirectional{}
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
		return fmt.Errorf("%s: %w", "decoding Unidirectional SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Unidirectional", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "dialoguePortion", content[offset:])
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return qualifyBERError(extErr, "dialoguePortion", "decoding", false)
				}
				var decoded_dialogueportion DialoguePortion
				if offset > len(content) || n_dialogueportion < 0 || n_dialogueportion > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if err := decoded_dialogueportion.UnmarshalBER(content[offset:offset+n_dialogueportion], opts...); err != nil {
					return err
				}
				v.DialoguePortion = &decoded_dialogueportion
				if offset > len(content) || n_dialogueportion < 0 || n_dialogueportion > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dialogueportion
			}
		}
	}
	// Decode components
	if offset >= len(content) {
		return fmt.Errorf("missing required field components")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 12 {
			return fmt.Errorf("expected tag [%s %d] for components, got %s", "APPLICATION", 12, reqTag_)
		}
	}
	{
		v.ComponentsIndef_ = false
		ber.MarkPreflightTarget(opts, "components", content[offset:])
		// Decode nested SEQUENCE_OF (UnidirectionalComponentsBound)
		_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_components != nil {
			return qualifyBERError(tlvErr_components, "components", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_components < 0 || n_components > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tlv_components := content[offset : offset+n_components]
		{
			_, tagSz_, _ := ber.DecodeTag(tlv_components)
			if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
				v.ComponentsIndef_ = true
			}
		}
		dec_components, unmErr := UnmarshalBERUnidirectionalComponentsBound(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "components", "decoding", false)
		}
		v.Components = dec_components
		if offset < 0 || offset >
			len(content) || n_components < 0 || n_components > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_components
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Unidirectional", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Begin to BER format.
func (v *Begin) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Begin receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Begin) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_otid, encodeErr_enc_otid := ber.EncodeOctetString([]byte(v.Otid))
	if encodeErr_enc_otid != nil {
		return nil, qualifyBERError(encodeErr_enc_otid, "otid", "encoding", false)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, qualifyBERError(tagErr_enc_otid, "otid", "encoding", false)
	}
	enc_otid = retagged_enc_otid
	children = append(children, enc_otid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", false)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalBERBeginComponentsBound(v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "Components", "encoding", false)
				}
			}
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes Begin to DER format.
func (v *Begin) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Begin receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_otid, encodeErr_enc_otid := ber.EncodeOctetString([]byte(v.Otid))
	if encodeErr_enc_otid != nil {
		return nil, qualifyBERError(encodeErr_enc_otid, "otid", "encoding", true)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, qualifyBERError(tagErr_enc_otid, "otid", "encoding", true)
	}
	enc_otid = retagged_enc_otid
	children = append(children, enc_otid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalDERBeginComponentsBound(v.Components)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", true)
		}
		children = append(children, enc_components...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding Begin as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes Begin from BER/DER format.
func (v *Begin) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Begin destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Begin
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = Begin{}
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
		return fmt.Errorf("%s: %w", "decoding Begin SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Begin", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode otid
	if offset >= len(content) {
		return fmt.Errorf("missing required field otid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 8 {
			return fmt.Errorf("expected tag [%s %d] for otid, got %s", "APPLICATION", 8, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "otid", content[offset:])
		decodedTag_otid, n_otid, rawVal_otid, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "otid", "decoding", false)
		}
		if decodedTag_otid.Class != tag.ClassApplication || decodedTag_otid.Number != 8 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_otid), "otid", "decoding", false)
		}
		decVal_otid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_otid.Constructed, rawVal_otid, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "otid", "decoding", false)
		}
		v.Otid = OrigTransactionID(decVal_otid)
		if offset > len(content) || n_otid < 0 || n_otid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_otid
		if len(v.Otid) < 1 || len(v.Otid) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "dialoguePortion", content[offset:])
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return qualifyBERError(extErr, "dialoguePortion", "decoding", false)
				}
				var decoded_dialogueportion DialoguePortion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if err := decoded_dialogueportion.UnmarshalBER(content[offset:offset+n_dialogueportion], opts...); err != nil {
					return err
				}
				v.DialoguePortion = &decoded_dialogueportion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dialogueportion
			}
		}
	}
	// Decode components
	v.ComponentsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "components", content[offset:])
				// Decode nested SEQUENCE_OF (BeginComponentsBound)
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_components != nil {
					return qualifyBERError(tlvErr_components, "components", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_components := content[offset : offset+n_components]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_components)
					if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				dec_components, unmErr := UnmarshalBERBeginComponentsBound(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "components", "decoding", false)
				}
				v.Components = dec_components
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_components
				if len((v.Components).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Begin", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes End to BER format.
func (v *End) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: End receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *End) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_dtid, encodeErr_enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	if encodeErr_enc_dtid != nil {
		return nil, qualifyBERError(encodeErr_enc_dtid, "dtid", "encoding", false)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, qualifyBERError(tagErr_enc_dtid, "dtid", "encoding", false)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", false)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalBEREndComponentsBound(v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "Components", "encoding", false)
				}
			}
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes End to DER format.
func (v *End) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: End receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_dtid, encodeErr_enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	if encodeErr_enc_dtid != nil {
		return nil, qualifyBERError(encodeErr_enc_dtid, "dtid", "encoding", true)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, qualifyBERError(tagErr_enc_dtid, "dtid", "encoding", true)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalDEREndComponentsBound(v.Components)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", true)
		}
		children = append(children, enc_components...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding End as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes End from BER/DER format.
func (v *End) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: End destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error { var probe End; return probe.UnmarshalBER(data, probeOpts...) })
	}
	*v = End{}
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
		return fmt.Errorf("%s: %w", "decoding End SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "End", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode dtid
	if offset >= len(content) {
		return fmt.Errorf("missing required field dtid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 9 {
			return fmt.Errorf("expected tag [%s %d] for dtid, got %s", "APPLICATION", 9, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "dtid", content[offset:])
		decodedTag_dtid, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "dtid", "decoding", false)
		}
		if decodedTag_dtid.Class != tag.ClassApplication || decodedTag_dtid.Number != 9 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dtid), "dtid", "decoding", false)
		}
		decVal_dtid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_dtid.Constructed, rawVal_dtid, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "dtid", "decoding", false)
		}
		v.Dtid = DestTransactionID(decVal_dtid)
		if offset > len(content) || n_dtid < 0 || n_dtid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_dtid
		if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "dialoguePortion", content[offset:])
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return qualifyBERError(extErr, "dialoguePortion", "decoding", false)
				}
				var decoded_dialogueportion DialoguePortion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if err := decoded_dialogueportion.UnmarshalBER(content[offset:offset+n_dialogueportion], opts...); err != nil {
					return err
				}
				v.DialoguePortion = &decoded_dialogueportion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dialogueportion
			}
		}
	}
	// Decode components
	v.ComponentsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "components", content[offset:])
				// Decode nested SEQUENCE_OF (EndComponentsBound)
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_components != nil {
					return qualifyBERError(tlvErr_components, "components", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_components := content[offset : offset+n_components]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_components)
					if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				dec_components, unmErr := UnmarshalBEREndComponentsBound(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "components", "decoding", false)
				}
				v.Components = dec_components
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_components
				if len((v.Components).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "End", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Continue to BER format.
func (v *Continue) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Continue receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Continue) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_otid, encodeErr_enc_otid := ber.EncodeOctetString([]byte(v.Otid))
	if encodeErr_enc_otid != nil {
		return nil, qualifyBERError(encodeErr_enc_otid, "otid", "encoding", false)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, qualifyBERError(tagErr_enc_otid, "otid", "encoding", false)
	}
	enc_otid = retagged_enc_otid
	children = append(children, enc_otid...)
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_dtid, encodeErr_enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	if encodeErr_enc_dtid != nil {
		return nil, qualifyBERError(encodeErr_enc_dtid, "dtid", "encoding", false)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, qualifyBERError(tagErr_enc_dtid, "dtid", "encoding", false)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", false)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalBERContinueComponentsBound(v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "Components", "encoding", false)
				}
			}
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes Continue to DER format.
func (v *Continue) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Continue receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_otid, encodeErr_enc_otid := ber.EncodeOctetString([]byte(v.Otid))
	if encodeErr_enc_otid != nil {
		return nil, qualifyBERError(encodeErr_enc_otid, "otid", "encoding", true)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, qualifyBERError(tagErr_enc_otid, "otid", "encoding", true)
	}
	enc_otid = retagged_enc_otid
	children = append(children, enc_otid...)
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_dtid, encodeErr_enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	if encodeErr_enc_dtid != nil {
		return nil, qualifyBERError(encodeErr_enc_dtid, "dtid", "encoding", true)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, qualifyBERError(tagErr_enc_dtid, "dtid", "encoding", true)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalDERContinueComponentsBound(v.Components)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", true)
		}
		children = append(children, enc_components...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding Continue as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes Continue from BER/DER format.
func (v *Continue) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Continue destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Continue
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = Continue{}
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
		return fmt.Errorf("%s: %w", "decoding Continue SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Continue", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode otid
	if offset >= len(content) {
		return fmt.Errorf("missing required field otid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 8 {
			return fmt.Errorf("expected tag [%s %d] for otid, got %s", "APPLICATION", 8, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "otid", content[offset:])
		decodedTag_otid, n_otid, rawVal_otid, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "otid", "decoding", false)
		}
		if decodedTag_otid.Class != tag.ClassApplication || decodedTag_otid.Number != 8 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_otid), "otid", "decoding", false)
		}
		decVal_otid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_otid.Constructed, rawVal_otid, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "otid", "decoding", false)
		}
		v.Otid = OrigTransactionID(decVal_otid)
		if offset > len(content) || n_otid < 0 || n_otid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_otid
		if len(v.Otid) < 1 || len(v.Otid) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode dtid
	if offset >= len(content) {
		return fmt.Errorf("missing required field dtid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 9 {
			return fmt.Errorf("expected tag [%s %d] for dtid, got %s", "APPLICATION", 9, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "dtid", content[offset:])
		decodedTag_dtid, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "dtid", "decoding", false)
		}
		if decodedTag_dtid.Class != tag.ClassApplication || decodedTag_dtid.Number != 9 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dtid), "dtid", "decoding", false)
		}
		decVal_dtid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_dtid.Constructed, rawVal_dtid, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "dtid", "decoding", false)
		}
		v.Dtid = DestTransactionID(decVal_dtid)
		if offset < 0 || offset >
			len(content) || n_dtid < 0 || n_dtid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_dtid
		if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "dialoguePortion", content[offset:])
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return qualifyBERError(extErr, "dialoguePortion", "decoding", false)
				}
				var decoded_dialogueportion DialoguePortion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if err := decoded_dialogueportion.UnmarshalBER(content[offset:offset+n_dialogueportion], opts...); err != nil {
					return err
				}
				v.DialoguePortion = &decoded_dialogueportion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dialogueportion
			}
		}
	}
	// Decode components
	v.ComponentsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "components", content[offset:])
				// Decode nested SEQUENCE_OF (ContinueComponentsBound)
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_components != nil {
					return qualifyBERError(tlvErr_components, "components", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_components := content[offset : offset+n_components]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_components)
					if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				dec_components, unmErr := UnmarshalBERContinueComponentsBound(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "components", "decoding", false)
				}
				v.Components = dec_components
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_components
				if len((v.Components).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Continue", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Abort to BER format.
func (v *Abort) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Abort receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Abort) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_dtid, encodeErr_enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	if encodeErr_enc_dtid != nil {
		return nil, qualifyBERError(encodeErr_enc_dtid, "dtid", "encoding", false)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, qualifyBERError(tagErr_enc_dtid, "dtid", "encoding", false)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.Reason != nil {
		enc_reason, err := v.Reason.MarshalBER(ber.ChildEncodeOptions(opts, "reason")...)
		if err != nil {
			return nil, qualifyBERError(err, "reason", "encoding", false)
		}
		children = append(children, enc_reason...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes Abort to DER format.
func (v *Abort) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Abort receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_dtid, encodeErr_enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	if encodeErr_enc_dtid != nil {
		return nil, qualifyBERError(encodeErr_enc_dtid, "dtid", "encoding", true)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, qualifyBERError(tagErr_enc_dtid, "dtid", "encoding", true)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.Reason != nil {
		enc_reason, err := v.Reason.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reason", "encoding", true)
		}
		children = append(children, enc_reason...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding Abort as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes Abort from BER/DER format.
func (v *Abort) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Abort destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Abort
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = Abort{}
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
		return fmt.Errorf("%s: %w", "decoding Abort SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Abort", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode dtid
	if offset >= len(content) {
		return fmt.Errorf("missing required field dtid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 9 {
			return fmt.Errorf("expected tag [%s %d] for dtid, got %s", "APPLICATION", 9, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "dtid", content[offset:])
		decodedTag_dtid, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "dtid", "decoding", false)
		}
		if decodedTag_dtid.Class != tag.ClassApplication || decodedTag_dtid.Number != 9 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dtid), "dtid", "decoding", false)
		}
		decVal_dtid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_dtid.Constructed, rawVal_dtid, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "dtid", "decoding", false)
		}
		v.Dtid = DestTransactionID(decVal_dtid)
		if offset > len(content) || n_dtid < 0 || n_dtid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_dtid
		if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode reason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassApplication && peekTag.Number == 10) || (peekTag.Class == tag.ClassApplication && peekTag.Number == 11) {
				ber.MarkPreflightTarget(opts, "reason", content[offset:])
				// Decode nested CHOICE (AbortReason)
				_, n_reason, _, tlvErr_reason := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_reason != nil {
					return qualifyBERError(tlvErr_reason, "reason", "decoding", false)
				}
				var dec_reason AbortReason
				if offset < 0 || offset >
					len(content) || n_reason < 0 || n_reason > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_reason.UnmarshalBER(content[offset:offset+n_reason], ber.ChildDecodeOptions(opts, "reason")...); unmErr != nil {
					return qualifyBERError(unmErr, "reason", "decoding", false)
				}
				v.Reason = &dec_reason
				if offset < 0 || offset >
					len(content) || n_reason < 0 || n_reason > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_reason
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Abort", Cause: ber.ErrExtraData}
	}
	return nil
}

func (v *DialoguePortion) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("%w: EXTERNAL value is nil", ber.ErrInvalidValue)
	}
	if ber.BERReplayEnabled(opts) {
		if original := runtime.External(*v).UnchangedBER(); original != nil {
			return original, nil
		}
	}
	encoded, err := ber.EncodeExternal(runtime.External(*v), opts...)
	if err != nil {
		return nil, err
	}
	encoded, err = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 11, encoded)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *DialoguePortion) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EXTERNAL value is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeExternalDER(runtime.External(*v))
	if err != nil {
		return nil, err
	}
	encoded, err = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 11, encoded)
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *DialoguePortion) UnmarshalBER(data []byte, opts ...ber.DecodeOption) error {
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe DialoguePortion
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	if v == nil {
		return fmt.Errorf("%w: EXTERNAL destination is nil", ber.ErrInvalidValue)
	}
	t, n, value, err := ber.DecodeTLV(data, opts...)
	if err != nil {
		return err
	}
	if n != len(data) {
		return ber.ErrExtraData
	}
	if t.Class != tag.ClassApplication || t.Number != 11 || !t.Constructed {
		return fmt.Errorf("%w: EXTERNAL has tag %s", ber.ErrInvalidTag, t)
	}
	decoded, innerSize, err := ber.DecodeExternal(value, opts...)
	if err != nil {
		return err
	}
	if innerSize != len(value) {
		return ber.ErrExtraData
	}
	decoded.RememberBER(data)
	*v = DialoguePortion(decoded)
	return nil
}

// MarshalBERComponentPortion encodes a ComponentPortion list to BER.
func MarshalBERComponentPortion(collection *ComponentPortion, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERComponentPortion(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERComponentPortion(collection *ComponentPortion, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(opts, "ComponentPortion", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 12, Constructed: true}, children)
}

// MarshalDERComponentPortion encodes a ComponentPortion list to DER.
func MarshalDERComponentPortion(collection *ComponentPortion) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(nil, "ComponentPortion", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, encoded)
	if tagErr_encoded != nil {
		return nil, qualifyBERError(tagErr_encoded, "ComponentPortion", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ComponentPortion as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERComponentPortion decodes a ComponentPortion list from BER.
func UnmarshalBERComponentPortion(data []byte, opts ...ber.DecodeOption) (returnValue *ComponentPortion, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERComponentPortion(data, probeOpts...)
			return probeErr
		})
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding ComponentPortion", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, fmt.Errorf("%s: %w", "decoding ComponentPortion", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 12], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ComponentPortion", Cause: ber.ErrExtraData}
	}
	var result []ComponentPortionElemBound
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem ComponentPortionElemBound
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedCollectionLength(opts, "ComponentPortion", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &ComponentPortion{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERComponentPortion(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes Component to BER format.
func (v *Component) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Component receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Component) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ComponentChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice Component: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.BasicROS.MarshalBER(ber.ChildEncodeOptions(opts, "basicROS")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", false)
		}
		return enc_0, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice Component: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResultNotLast", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Component", v.Choice)
	}
}

// MarshalDER encodes Component to DER format.
func (v *Component) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Component receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ComponentChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice Component: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.BasicROS.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "basicROS", "encoding", true)
		}
		return enc_der_0, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice Component: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResultNotLast", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResultNotLast", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ComponentChoiceBasicROS:
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		case ComponentChoiceReturnResultNotLast:
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding Component as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes Component from BER/DER format.
func (v *Component) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Component destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Component
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = Component{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Component CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Component: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding Component CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Component", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = ComponentChoiceReturnResultNotLast
		ber.MarkPreflightTarget(opts, "returnResultNotLast", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResultNotLast", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultNotLast")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResultNotLast", "decoding", false)
		}
		v.ReturnResultNotLast = &dec
	} else {
		v.Choice = ComponentChoiceBasicROS
		var dec ComponentBasicROSBound
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "basicROS")...); unmErr != nil {
			return qualifyBERError(unmErr, "basicROS", "decoding", false)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBER encodes TCInvokeIdSet to BER format.
func (v *TCInvokeIdSet) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCInvokeIdSet receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCInvokeIdSet) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if v.Choice == TCInvokeIdSetChoicePresent {
		if v.Present == nil {
			return nil, fmt.Errorf("encoding TCInvokeIdSet violates WITH COMPONENTS: Present must carry a constrained value")
		}
	}
	if v.Choice == TCInvokeIdSetChoiceAbsent {
		if constraintErr := ber.CheckEncodedValue(opts, "absent", "WITH COMPONENTS: absent ABSENT", "absent"); constraintErr != nil {
			return nil, constraintErr
		}
	}
	switch v.Choice {
	case TCInvokeIdSetChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice TCInvokeIdSet: present is nil", ber.ErrInvalidValue)
		}
		enc_0 := ber.EncodeInteger(int64(*v.Present))
		if !(int64(*v.Present) >= -128 && int64(*v.Present) <= 127) {
			if constraintErr := ber.CheckEncodedValue(opts, "present", "(-128..127)", fmt.Sprint(int64(*v.Present))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case TCInvokeIdSetChoiceAbsent:
		enc_1 := ber.EncodeNull()
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCInvokeIdSet", v.Choice)
	}
}

// MarshalDER encodes TCInvokeIdSet to DER format.
func (v *TCInvokeIdSet) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCInvokeIdSet receiver is nil", ber.ErrInvalidValue)
	}
	if v.Choice == TCInvokeIdSetChoicePresent {
		if v.Present == nil {
			return nil, fmt.Errorf("encoding TCInvokeIdSet violates WITH COMPONENTS: Present must carry a constrained value")
		}
	}
	if v.Choice == TCInvokeIdSetChoiceAbsent {
		if constraintErr := ber.CheckEncodedValue(nil, "absent", "WITH COMPONENTS: absent ABSENT", "absent"); constraintErr != nil {
			return nil, constraintErr
		}
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCInvokeIdSetChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case TCInvokeIdSetChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCInvokeIdSet as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCInvokeIdSet from BER/DER format.
func (v *TCInvokeIdSet) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCInvokeIdSet destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCInvokeIdSet
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCInvokeIdSet{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCInvokeIdSet CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCInvokeIdSet: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCInvokeIdSet CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCInvokeIdSet", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = TCInvokeIdSetChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		decVal, _, intErr := ber.DecodeInteger(choiceData, opts...)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = &decVal
		if !(int64(*v.Present) >= -128 && int64(*v.Present) <= 127) {
			if constraintErr := ber.CheckDecodedValue(opts, "present", "(-128..127)", fmt.Sprint(int64(*v.Present))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = TCInvokeIdSetChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, nullErr := ber.DecodeNull(choiceData, opts...)
		if nullErr != nil {
			return qualifyBERError(nullErr, "absent", "decoding", false)
		}
	} else {
		return fmt.Errorf("unknown tag %s for TCInvokeIdSet CHOICE", peekTag)
	}
	if v.Choice == TCInvokeIdSetChoicePresent {
		if v.Present == nil {
			return fmt.Errorf("decoded TCInvokeIdSet violates WITH COMPONENTS: Present must carry a constrained value")
		}
	}
	if v.Choice == TCInvokeIdSetChoiceAbsent {
		if constraintErr := ber.CheckDecodedValue(opts, "absent", "WITH COMPONENTS: absent ABSENT", "absent"); constraintErr != nil {
			return constraintErr
		}
	}
	return nil
}

// MarshalBER encodes TCMessageUnidirectionalComponentsElemBasicROSInvokeBound to BER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSInvokeBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageUnidirectionalComponentsElemBasicROSInvokeBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER(ber.ChildEncodeOptions(opts, "linkedId")...)
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", false)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageUnidirectionalComponentsElemBasicROSInvokeBound to DER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSInvokeBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", true)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		children = append(children, enc_argument...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageUnidirectionalComponentsElemBasicROSInvokeBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageUnidirectionalComponentsElemBasicROSInvokeBound from BER/DER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSInvokeBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSInvokeBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageUnidirectionalComponentsElemBasicROSInvokeBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageUnidirectionalComponentsElemBasicROSInvokeBound{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageUnidirectionalComponentsElemBasicROSInvokeBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageUnidirectionalComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (TCInvokeIdSet)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "linkedId", content[offset:])
				// Decode nested CHOICE (TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_linkedid != nil {
					return qualifyBERError(tlvErr_linkedid, "linkedId", "decoding", false)
				}
				var dec_linkedid TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_linkedid.UnmarshalBER(content[offset:offset+n_linkedid], ber.ChildDecodeOptions(opts, "linkedId")...); unmErr != nil {
					return qualifyBERError(unmErr, "linkedId", "decoding", false)
				}
				v.LinkedId = &dec_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode argument
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "argument", content[offset:])
		_, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_argument != nil {
			return qualifyBERError(tlvErr_argument, "argument", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "argument", content[offset:], n_argument)
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_argument := runtime.RawValue{Bytes: content[offset : offset+n_argument]}
		v.Argument = &tmp_argument
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageUnidirectionalComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageUnidirectionalComponentsElemBasicROSBound to BER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageUnidirectionalComponentsElemBasicROSBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", false)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResult.MarshalBER(ber.ChildEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResult", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnError", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "reject", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageUnidirectionalComponentsElemBasicROSBound", v.Choice)
	}
}

// MarshalDER encodes TCMessageUnidirectionalComponentsElemBasicROSBound to DER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "invoke", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "invoke", "encoding", true)
		}
		return enc_der_0, nil
	case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResult", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResult", "encoding", true)
		}
		return enc_der_1, nil
	case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "returnError", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "returnError", "encoding", true)
		}
		return enc_der_2, nil
	case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "reject", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "reject", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageUnidirectionalComponentsElemBasicROSBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageUnidirectionalComponentsElemBasicROSBound from BER/DER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageUnidirectionalComponentsElemBasicROSBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageUnidirectionalComponentsElemBasicROSBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageUnidirectionalComponentsElemBasicROSBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageUnidirectionalComponentsElemBasicROSBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageUnidirectionalComponentsElemBasicROSBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageUnidirectionalComponentsElemBasicROSBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec TCMessageUnidirectionalComponentsElemBasicROSInvokeBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = TCMessageUnidirectionalComponentsElemBasicROSBoundChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for TCMessageUnidirectionalComponentsElemBasicROSBound CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes TCMessageUnidirectionalComponentsElemBound to BER format.
func (v *TCMessageUnidirectionalComponentsElemBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageUnidirectionalComponentsElemBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageUnidirectionalComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.BasicROS.MarshalBER(ber.ChildEncodeOptions(opts, "basicROS")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", false)
		}
		return enc_0, nil
	case TCMessageUnidirectionalComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResultNotLast", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageUnidirectionalComponentsElemBound", v.Choice)
	}
}

// MarshalDER encodes TCMessageUnidirectionalComponentsElemBound to DER format.
func (v *TCMessageUnidirectionalComponentsElemBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case TCMessageUnidirectionalComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.BasicROS.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "basicROS", "encoding", true)
		}
		return enc_der_0, nil
	case TCMessageUnidirectionalComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResultNotLast", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResultNotLast", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageUnidirectionalComponentsElemBoundChoiceBasicROS:
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		case TCMessageUnidirectionalComponentsElemBoundChoiceReturnResultNotLast:
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageUnidirectionalComponentsElemBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageUnidirectionalComponentsElemBound from BER/DER format.
func (v *TCMessageUnidirectionalComponentsElemBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageUnidirectionalComponentsElemBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageUnidirectionalComponentsElemBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageUnidirectionalComponentsElemBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageUnidirectionalComponentsElemBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageUnidirectionalComponentsElemBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageUnidirectionalComponentsElemBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = TCMessageUnidirectionalComponentsElemBoundChoiceReturnResultNotLast
		ber.MarkPreflightTarget(opts, "returnResultNotLast", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResultNotLast", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultNotLast")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResultNotLast", "decoding", false)
		}
		v.ReturnResultNotLast = &dec
	} else {
		v.Choice = TCMessageUnidirectionalComponentsElemBoundChoiceBasicROS
		var dec TCMessageUnidirectionalComponentsElemBasicROSBound
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "basicROS")...); unmErr != nil {
			return qualifyBERError(unmErr, "basicROS", "decoding", false)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBERTCMessageUnidirectionalComponentsBound encodes a TCMessageUnidirectionalComponentsBound list to BER.
func MarshalBERTCMessageUnidirectionalComponentsBound(collection *TCMessageUnidirectionalComponentsBound, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERTCMessageUnidirectionalComponentsBound(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERTCMessageUnidirectionalComponentsBound(collection *TCMessageUnidirectionalComponentsBound, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 12, Constructed: true}, children)
}

// MarshalDERTCMessageUnidirectionalComponentsBound encodes a TCMessageUnidirectionalComponentsBound list to DER.
func MarshalDERTCMessageUnidirectionalComponentsBound(collection *TCMessageUnidirectionalComponentsBound) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, encoded)
	if tagErr_encoded != nil {
		return nil, qualifyBERError(tagErr_encoded, "TCMessageUnidirectionalComponentsBound", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageUnidirectionalComponentsBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERTCMessageUnidirectionalComponentsBound decodes a TCMessageUnidirectionalComponentsBound list from BER.
func UnmarshalBERTCMessageUnidirectionalComponentsBound(data []byte, opts ...ber.DecodeOption) (returnValue *TCMessageUnidirectionalComponentsBound, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERTCMessageUnidirectionalComponentsBound(data, probeOpts...)
			return probeErr
		})
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding TCMessageUnidirectionalComponentsBound", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, fmt.Errorf("%s: %w", "decoding TCMessageUnidirectionalComponentsBound", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 12], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TCMessageUnidirectionalComponentsBound", Cause: ber.ErrExtraData}
	}
	var result []TCMessageUnidirectionalComponentsElemBound
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem TCMessageUnidirectionalComponentsElemBound
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	decoded := &TCMessageUnidirectionalComponentsBound{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERTCMessageUnidirectionalComponentsBound(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes TCMessageUnidirectionalBound to BER format.
func (v *TCMessageUnidirectionalBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageUnidirectionalBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", false)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "components", "encoding", false)
	}
	if len((v.Components).Values) < 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_components, err := MarshalBERTCMessageUnidirectionalComponentsBound(v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
	if err != nil {
		return nil, qualifyBERError(err, "components", "encoding", false)
	}
	if ber.BERReplayEnabled(opts) && v.ComponentsIndef_ {
		indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		{
			var encodeErr error
			enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "Components", "encoding", false)
			}
		}
	}
	children = append(children, enc_components...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageUnidirectionalBound to DER format.
func (v *TCMessageUnidirectionalBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "components", "encoding", true)
	}
	if len((v.Components).Values) < 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_components, err := MarshalDERTCMessageUnidirectionalComponentsBound(v.Components)
	if err != nil {
		return nil, qualifyBERError(err, "components", "encoding", true)
	}
	children = append(children, enc_components...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageUnidirectionalBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageUnidirectionalBound from BER/DER format.
func (v *TCMessageUnidirectionalBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageUnidirectionalBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageUnidirectionalBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageUnidirectionalBound{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageUnidirectionalBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageUnidirectionalBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "dialoguePortion", content[offset:])
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return qualifyBERError(extErr, "dialoguePortion", "decoding", false)
				}
				var decoded_dialogueportion DialoguePortion
				if offset > len(content) || n_dialogueportion < 0 || n_dialogueportion > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if err := decoded_dialogueportion.UnmarshalBER(content[offset:offset+n_dialogueportion], opts...); err != nil {
					return err
				}
				v.DialoguePortion = &decoded_dialogueportion
				if offset > len(content) || n_dialogueportion < 0 || n_dialogueportion > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dialogueportion
			}
		}
	}
	// Decode components
	if offset >= len(content) {
		return fmt.Errorf("missing required field components")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 12 {
			return fmt.Errorf("expected tag [%s %d] for components, got %s", "APPLICATION", 12, reqTag_)
		}
	}
	{
		v.ComponentsIndef_ = false
		ber.MarkPreflightTarget(opts, "components", content[offset:])
		// Decode nested SEQUENCE_OF (TCMessageUnidirectionalComponentsBound)
		_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_components != nil {
			return qualifyBERError(tlvErr_components, "components", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_components < 0 || n_components > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tlv_components := content[offset : offset+n_components]
		{
			_, tagSz_, _ := ber.DecodeTag(tlv_components)
			if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
				v.ComponentsIndef_ = true
			}
		}
		dec_components, unmErr := UnmarshalBERTCMessageUnidirectionalComponentsBound(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "components", "decoding", false)
		}
		v.Components = dec_components
		if offset < 0 || offset >
			len(content) || n_components < 0 || n_components > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_components
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageUnidirectionalBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageBeginComponentsElemBasicROSInvokeBound to BER format.
func (v *TCMessageBeginComponentsElemBasicROSInvokeBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageBeginComponentsElemBasicROSInvokeBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER(ber.ChildEncodeOptions(opts, "linkedId")...)
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", false)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageBeginComponentsElemBasicROSInvokeBound to DER format.
func (v *TCMessageBeginComponentsElemBasicROSInvokeBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", true)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		children = append(children, enc_argument...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageBeginComponentsElemBasicROSInvokeBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageBeginComponentsElemBasicROSInvokeBound from BER/DER format.
func (v *TCMessageBeginComponentsElemBasicROSInvokeBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSInvokeBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageBeginComponentsElemBasicROSInvokeBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageBeginComponentsElemBasicROSInvokeBound{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageBeginComponentsElemBasicROSInvokeBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageBeginComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (TCInvokeIdSet)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "linkedId", content[offset:])
				// Decode nested CHOICE (TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_linkedid != nil {
					return qualifyBERError(tlvErr_linkedid, "linkedId", "decoding", false)
				}
				var dec_linkedid TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_linkedid.UnmarshalBER(content[offset:offset+n_linkedid], ber.ChildDecodeOptions(opts, "linkedId")...); unmErr != nil {
					return qualifyBERError(unmErr, "linkedId", "decoding", false)
				}
				v.LinkedId = &dec_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode argument
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "argument", content[offset:])
		_, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_argument != nil {
			return qualifyBERError(tlvErr_argument, "argument", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "argument", content[offset:], n_argument)
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_argument := runtime.RawValue{Bytes: content[offset : offset+n_argument]}
		v.Argument = &tmp_argument
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageBeginComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageBeginComponentsElemBasicROSBound to BER format.
func (v *TCMessageBeginComponentsElemBasicROSBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageBeginComponentsElemBasicROSBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageBeginComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", false)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case TCMessageBeginComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResult.MarshalBER(ber.ChildEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResult", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case TCMessageBeginComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnError", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case TCMessageBeginComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "reject", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageBeginComponentsElemBasicROSBound", v.Choice)
	}
}

// MarshalDER encodes TCMessageBeginComponentsElemBasicROSBound to DER format.
func (v *TCMessageBeginComponentsElemBasicROSBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case TCMessageBeginComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "invoke", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "invoke", "encoding", true)
		}
		return enc_der_0, nil
	case TCMessageBeginComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResult", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResult", "encoding", true)
		}
		return enc_der_1, nil
	case TCMessageBeginComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "returnError", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "returnError", "encoding", true)
		}
		return enc_der_2, nil
	case TCMessageBeginComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "reject", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "reject", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageBeginComponentsElemBasicROSBoundChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case TCMessageBeginComponentsElemBasicROSBoundChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case TCMessageBeginComponentsElemBasicROSBoundChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case TCMessageBeginComponentsElemBasicROSBoundChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageBeginComponentsElemBasicROSBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageBeginComponentsElemBasicROSBound from BER/DER format.
func (v *TCMessageBeginComponentsElemBasicROSBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageBeginComponentsElemBasicROSBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageBeginComponentsElemBasicROSBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageBeginComponentsElemBasicROSBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageBeginComponentsElemBasicROSBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageBeginComponentsElemBasicROSBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageBeginComponentsElemBasicROSBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = TCMessageBeginComponentsElemBasicROSBoundChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec TCMessageBeginComponentsElemBasicROSInvokeBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = TCMessageBeginComponentsElemBasicROSBoundChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = TCMessageBeginComponentsElemBasicROSBoundChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = TCMessageBeginComponentsElemBasicROSBoundChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for TCMessageBeginComponentsElemBasicROSBound CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes TCMessageBeginComponentsElemBound to BER format.
func (v *TCMessageBeginComponentsElemBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageBeginComponentsElemBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageBeginComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.BasicROS.MarshalBER(ber.ChildEncodeOptions(opts, "basicROS")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", false)
		}
		return enc_0, nil
	case TCMessageBeginComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResultNotLast", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageBeginComponentsElemBound", v.Choice)
	}
}

// MarshalDER encodes TCMessageBeginComponentsElemBound to DER format.
func (v *TCMessageBeginComponentsElemBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case TCMessageBeginComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.BasicROS.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "basicROS", "encoding", true)
		}
		return enc_der_0, nil
	case TCMessageBeginComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResultNotLast", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResultNotLast", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageBeginComponentsElemBoundChoiceBasicROS:
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		case TCMessageBeginComponentsElemBoundChoiceReturnResultNotLast:
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageBeginComponentsElemBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageBeginComponentsElemBound from BER/DER format.
func (v *TCMessageBeginComponentsElemBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageBeginComponentsElemBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageBeginComponentsElemBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageBeginComponentsElemBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageBeginComponentsElemBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageBeginComponentsElemBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageBeginComponentsElemBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageBeginComponentsElemBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = TCMessageBeginComponentsElemBoundChoiceReturnResultNotLast
		ber.MarkPreflightTarget(opts, "returnResultNotLast", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResultNotLast", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultNotLast")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResultNotLast", "decoding", false)
		}
		v.ReturnResultNotLast = &dec
	} else {
		v.Choice = TCMessageBeginComponentsElemBoundChoiceBasicROS
		var dec TCMessageBeginComponentsElemBasicROSBound
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "basicROS")...); unmErr != nil {
			return qualifyBERError(unmErr, "basicROS", "decoding", false)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBERTCMessageBeginComponentsBound encodes a TCMessageBeginComponentsBound list to BER.
func MarshalBERTCMessageBeginComponentsBound(collection *TCMessageBeginComponentsBound, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERTCMessageBeginComponentsBound(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERTCMessageBeginComponentsBound(collection *TCMessageBeginComponentsBound, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 12, Constructed: true}, children)
}

// MarshalDERTCMessageBeginComponentsBound encodes a TCMessageBeginComponentsBound list to DER.
func MarshalDERTCMessageBeginComponentsBound(collection *TCMessageBeginComponentsBound) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, encoded)
	if tagErr_encoded != nil {
		return nil, qualifyBERError(tagErr_encoded, "TCMessageBeginComponentsBound", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageBeginComponentsBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERTCMessageBeginComponentsBound decodes a TCMessageBeginComponentsBound list from BER.
func UnmarshalBERTCMessageBeginComponentsBound(data []byte, opts ...ber.DecodeOption) (returnValue *TCMessageBeginComponentsBound, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERTCMessageBeginComponentsBound(data, probeOpts...)
			return probeErr
		})
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding TCMessageBeginComponentsBound", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, fmt.Errorf("%s: %w", "decoding TCMessageBeginComponentsBound", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 12], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TCMessageBeginComponentsBound", Cause: ber.ErrExtraData}
	}
	var result []TCMessageBeginComponentsElemBound
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem TCMessageBeginComponentsElemBound
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	decoded := &TCMessageBeginComponentsBound{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERTCMessageBeginComponentsBound(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes TCMessageBeginBound to BER format.
func (v *TCMessageBeginBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageBeginBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_otid, encodeErr_enc_otid := ber.EncodeOctetString([]byte(v.Otid))
	if encodeErr_enc_otid != nil {
		return nil, qualifyBERError(encodeErr_enc_otid, "otid", "encoding", false)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, qualifyBERError(tagErr_enc_otid, "otid", "encoding", false)
	}
	enc_otid = retagged_enc_otid
	children = append(children, enc_otid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", false)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalBERTCMessageBeginComponentsBound(v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "Components", "encoding", false)
				}
			}
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageBeginBound to DER format.
func (v *TCMessageBeginBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_otid, encodeErr_enc_otid := ber.EncodeOctetString([]byte(v.Otid))
	if encodeErr_enc_otid != nil {
		return nil, qualifyBERError(encodeErr_enc_otid, "otid", "encoding", true)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, qualifyBERError(tagErr_enc_otid, "otid", "encoding", true)
	}
	enc_otid = retagged_enc_otid
	children = append(children, enc_otid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalDERTCMessageBeginComponentsBound(v.Components)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", true)
		}
		children = append(children, enc_components...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageBeginBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageBeginBound from BER/DER format.
func (v *TCMessageBeginBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageBeginBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageBeginBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageBeginBound{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageBeginBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageBeginBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode otid
	if offset >= len(content) {
		return fmt.Errorf("missing required field otid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 8 {
			return fmt.Errorf("expected tag [%s %d] for otid, got %s", "APPLICATION", 8, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "otid", content[offset:])
		decodedTag_otid, n_otid, rawVal_otid, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "otid", "decoding", false)
		}
		if decodedTag_otid.Class != tag.ClassApplication || decodedTag_otid.Number != 8 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_otid), "otid", "decoding", false)
		}
		decVal_otid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_otid.Constructed, rawVal_otid, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "otid", "decoding", false)
		}
		v.Otid = OrigTransactionID(decVal_otid)
		if offset > len(content) || n_otid < 0 || n_otid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_otid
		if len(v.Otid) < 1 || len(v.Otid) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "dialoguePortion", content[offset:])
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return qualifyBERError(extErr, "dialoguePortion", "decoding", false)
				}
				var decoded_dialogueportion DialoguePortion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if err := decoded_dialogueportion.UnmarshalBER(content[offset:offset+n_dialogueportion], opts...); err != nil {
					return err
				}
				v.DialoguePortion = &decoded_dialogueportion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dialogueportion
			}
		}
	}
	// Decode components
	v.ComponentsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "components", content[offset:])
				// Decode nested SEQUENCE_OF (TCMessageBeginComponentsBound)
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_components != nil {
					return qualifyBERError(tlvErr_components, "components", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_components := content[offset : offset+n_components]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_components)
					if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				dec_components, unmErr := UnmarshalBERTCMessageBeginComponentsBound(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "components", "decoding", false)
				}
				v.Components = dec_components
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_components
				if len((v.Components).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageBeginBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageEndComponentsElemBasicROSInvokeBound to BER format.
func (v *TCMessageEndComponentsElemBasicROSInvokeBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageEndComponentsElemBasicROSInvokeBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER(ber.ChildEncodeOptions(opts, "linkedId")...)
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", false)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageEndComponentsElemBasicROSInvokeBound to DER format.
func (v *TCMessageEndComponentsElemBasicROSInvokeBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", true)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		children = append(children, enc_argument...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageEndComponentsElemBasicROSInvokeBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageEndComponentsElemBasicROSInvokeBound from BER/DER format.
func (v *TCMessageEndComponentsElemBasicROSInvokeBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSInvokeBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageEndComponentsElemBasicROSInvokeBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageEndComponentsElemBasicROSInvokeBound{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageEndComponentsElemBasicROSInvokeBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageEndComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (TCInvokeIdSet)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "linkedId", content[offset:])
				// Decode nested CHOICE (TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_linkedid != nil {
					return qualifyBERError(tlvErr_linkedid, "linkedId", "decoding", false)
				}
				var dec_linkedid TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_linkedid.UnmarshalBER(content[offset:offset+n_linkedid], ber.ChildDecodeOptions(opts, "linkedId")...); unmErr != nil {
					return qualifyBERError(unmErr, "linkedId", "decoding", false)
				}
				v.LinkedId = &dec_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode argument
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "argument", content[offset:])
		_, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_argument != nil {
			return qualifyBERError(tlvErr_argument, "argument", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "argument", content[offset:], n_argument)
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_argument := runtime.RawValue{Bytes: content[offset : offset+n_argument]}
		v.Argument = &tmp_argument
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageEndComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageEndComponentsElemBasicROSBound to BER format.
func (v *TCMessageEndComponentsElemBasicROSBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageEndComponentsElemBasicROSBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageEndComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", false)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case TCMessageEndComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResult.MarshalBER(ber.ChildEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResult", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case TCMessageEndComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnError", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case TCMessageEndComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "reject", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageEndComponentsElemBasicROSBound", v.Choice)
	}
}

// MarshalDER encodes TCMessageEndComponentsElemBasicROSBound to DER format.
func (v *TCMessageEndComponentsElemBasicROSBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case TCMessageEndComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "invoke", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "invoke", "encoding", true)
		}
		return enc_der_0, nil
	case TCMessageEndComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResult", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResult", "encoding", true)
		}
		return enc_der_1, nil
	case TCMessageEndComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "returnError", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "returnError", "encoding", true)
		}
		return enc_der_2, nil
	case TCMessageEndComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "reject", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "reject", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageEndComponentsElemBasicROSBoundChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case TCMessageEndComponentsElemBasicROSBoundChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case TCMessageEndComponentsElemBasicROSBoundChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case TCMessageEndComponentsElemBasicROSBoundChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageEndComponentsElemBasicROSBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageEndComponentsElemBasicROSBound from BER/DER format.
func (v *TCMessageEndComponentsElemBasicROSBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageEndComponentsElemBasicROSBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageEndComponentsElemBasicROSBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageEndComponentsElemBasicROSBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageEndComponentsElemBasicROSBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageEndComponentsElemBasicROSBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageEndComponentsElemBasicROSBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = TCMessageEndComponentsElemBasicROSBoundChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec TCMessageEndComponentsElemBasicROSInvokeBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = TCMessageEndComponentsElemBasicROSBoundChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = TCMessageEndComponentsElemBasicROSBoundChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = TCMessageEndComponentsElemBasicROSBoundChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for TCMessageEndComponentsElemBasicROSBound CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes TCMessageEndComponentsElemBound to BER format.
func (v *TCMessageEndComponentsElemBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageEndComponentsElemBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageEndComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.BasicROS.MarshalBER(ber.ChildEncodeOptions(opts, "basicROS")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", false)
		}
		return enc_0, nil
	case TCMessageEndComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResultNotLast", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageEndComponentsElemBound", v.Choice)
	}
}

// MarshalDER encodes TCMessageEndComponentsElemBound to DER format.
func (v *TCMessageEndComponentsElemBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case TCMessageEndComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.BasicROS.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "basicROS", "encoding", true)
		}
		return enc_der_0, nil
	case TCMessageEndComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResultNotLast", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResultNotLast", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageEndComponentsElemBoundChoiceBasicROS:
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		case TCMessageEndComponentsElemBoundChoiceReturnResultNotLast:
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageEndComponentsElemBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageEndComponentsElemBound from BER/DER format.
func (v *TCMessageEndComponentsElemBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageEndComponentsElemBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageEndComponentsElemBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageEndComponentsElemBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageEndComponentsElemBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageEndComponentsElemBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageEndComponentsElemBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageEndComponentsElemBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = TCMessageEndComponentsElemBoundChoiceReturnResultNotLast
		ber.MarkPreflightTarget(opts, "returnResultNotLast", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResultNotLast", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultNotLast")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResultNotLast", "decoding", false)
		}
		v.ReturnResultNotLast = &dec
	} else {
		v.Choice = TCMessageEndComponentsElemBoundChoiceBasicROS
		var dec TCMessageEndComponentsElemBasicROSBound
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "basicROS")...); unmErr != nil {
			return qualifyBERError(unmErr, "basicROS", "decoding", false)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBERTCMessageEndComponentsBound encodes a TCMessageEndComponentsBound list to BER.
func MarshalBERTCMessageEndComponentsBound(collection *TCMessageEndComponentsBound, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERTCMessageEndComponentsBound(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERTCMessageEndComponentsBound(collection *TCMessageEndComponentsBound, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 12, Constructed: true}, children)
}

// MarshalDERTCMessageEndComponentsBound encodes a TCMessageEndComponentsBound list to DER.
func MarshalDERTCMessageEndComponentsBound(collection *TCMessageEndComponentsBound) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, encoded)
	if tagErr_encoded != nil {
		return nil, qualifyBERError(tagErr_encoded, "TCMessageEndComponentsBound", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageEndComponentsBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERTCMessageEndComponentsBound decodes a TCMessageEndComponentsBound list from BER.
func UnmarshalBERTCMessageEndComponentsBound(data []byte, opts ...ber.DecodeOption) (returnValue *TCMessageEndComponentsBound, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERTCMessageEndComponentsBound(data, probeOpts...)
			return probeErr
		})
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding TCMessageEndComponentsBound", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, fmt.Errorf("%s: %w", "decoding TCMessageEndComponentsBound", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 12], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TCMessageEndComponentsBound", Cause: ber.ErrExtraData}
	}
	var result []TCMessageEndComponentsElemBound
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem TCMessageEndComponentsElemBound
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	decoded := &TCMessageEndComponentsBound{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERTCMessageEndComponentsBound(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes TCMessageEndBound to BER format.
func (v *TCMessageEndBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageEndBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_dtid, encodeErr_enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	if encodeErr_enc_dtid != nil {
		return nil, qualifyBERError(encodeErr_enc_dtid, "dtid", "encoding", false)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, qualifyBERError(tagErr_enc_dtid, "dtid", "encoding", false)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", false)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalBERTCMessageEndComponentsBound(v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "Components", "encoding", false)
				}
			}
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageEndBound to DER format.
func (v *TCMessageEndBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_dtid, encodeErr_enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	if encodeErr_enc_dtid != nil {
		return nil, qualifyBERError(encodeErr_enc_dtid, "dtid", "encoding", true)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, qualifyBERError(tagErr_enc_dtid, "dtid", "encoding", true)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalDERTCMessageEndComponentsBound(v.Components)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", true)
		}
		children = append(children, enc_components...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageEndBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageEndBound from BER/DER format.
func (v *TCMessageEndBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageEndBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageEndBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageEndBound{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageEndBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageEndBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode dtid
	if offset >= len(content) {
		return fmt.Errorf("missing required field dtid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 9 {
			return fmt.Errorf("expected tag [%s %d] for dtid, got %s", "APPLICATION", 9, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "dtid", content[offset:])
		decodedTag_dtid, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "dtid", "decoding", false)
		}
		if decodedTag_dtid.Class != tag.ClassApplication || decodedTag_dtid.Number != 9 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dtid), "dtid", "decoding", false)
		}
		decVal_dtid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_dtid.Constructed, rawVal_dtid, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "dtid", "decoding", false)
		}
		v.Dtid = DestTransactionID(decVal_dtid)
		if offset > len(content) || n_dtid < 0 || n_dtid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_dtid
		if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "dialoguePortion", content[offset:])
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return qualifyBERError(extErr, "dialoguePortion", "decoding", false)
				}
				var decoded_dialogueportion DialoguePortion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if err := decoded_dialogueportion.UnmarshalBER(content[offset:offset+n_dialogueportion], opts...); err != nil {
					return err
				}
				v.DialoguePortion = &decoded_dialogueportion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dialogueportion
			}
		}
	}
	// Decode components
	v.ComponentsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "components", content[offset:])
				// Decode nested SEQUENCE_OF (TCMessageEndComponentsBound)
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_components != nil {
					return qualifyBERError(tlvErr_components, "components", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_components := content[offset : offset+n_components]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_components)
					if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				dec_components, unmErr := UnmarshalBERTCMessageEndComponentsBound(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "components", "decoding", false)
				}
				v.Components = dec_components
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_components
				if len((v.Components).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageEndBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageContinueComponentsElemBasicROSInvokeBound to BER format.
func (v *TCMessageContinueComponentsElemBasicROSInvokeBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageContinueComponentsElemBasicROSInvokeBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER(ber.ChildEncodeOptions(opts, "linkedId")...)
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", false)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageContinueComponentsElemBasicROSInvokeBound to DER format.
func (v *TCMessageContinueComponentsElemBasicROSInvokeBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", true)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		children = append(children, enc_argument...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageContinueComponentsElemBasicROSInvokeBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageContinueComponentsElemBasicROSInvokeBound from BER/DER format.
func (v *TCMessageContinueComponentsElemBasicROSInvokeBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSInvokeBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageContinueComponentsElemBasicROSInvokeBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageContinueComponentsElemBasicROSInvokeBound{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageContinueComponentsElemBasicROSInvokeBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageContinueComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (TCInvokeIdSet)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "linkedId", content[offset:])
				// Decode nested CHOICE (TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_linkedid != nil {
					return qualifyBERError(tlvErr_linkedid, "linkedId", "decoding", false)
				}
				var dec_linkedid TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_linkedid.UnmarshalBER(content[offset:offset+n_linkedid], ber.ChildDecodeOptions(opts, "linkedId")...); unmErr != nil {
					return qualifyBERError(unmErr, "linkedId", "decoding", false)
				}
				v.LinkedId = &dec_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode argument
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "argument", content[offset:])
		_, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_argument != nil {
			return qualifyBERError(tlvErr_argument, "argument", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "argument", content[offset:], n_argument)
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_argument := runtime.RawValue{Bytes: content[offset : offset+n_argument]}
		v.Argument = &tmp_argument
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageContinueComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageContinueComponentsElemBasicROSBound to BER format.
func (v *TCMessageContinueComponentsElemBasicROSBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageContinueComponentsElemBasicROSBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageContinueComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", false)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case TCMessageContinueComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResult.MarshalBER(ber.ChildEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResult", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case TCMessageContinueComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnError", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case TCMessageContinueComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "reject", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageContinueComponentsElemBasicROSBound", v.Choice)
	}
}

// MarshalDER encodes TCMessageContinueComponentsElemBasicROSBound to DER format.
func (v *TCMessageContinueComponentsElemBasicROSBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case TCMessageContinueComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "invoke", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "invoke", "encoding", true)
		}
		return enc_der_0, nil
	case TCMessageContinueComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResult", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResult", "encoding", true)
		}
		return enc_der_1, nil
	case TCMessageContinueComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "returnError", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "returnError", "encoding", true)
		}
		return enc_der_2, nil
	case TCMessageContinueComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "reject", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "reject", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageContinueComponentsElemBasicROSBoundChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case TCMessageContinueComponentsElemBasicROSBoundChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case TCMessageContinueComponentsElemBasicROSBoundChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case TCMessageContinueComponentsElemBasicROSBoundChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageContinueComponentsElemBasicROSBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageContinueComponentsElemBasicROSBound from BER/DER format.
func (v *TCMessageContinueComponentsElemBasicROSBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageContinueComponentsElemBasicROSBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageContinueComponentsElemBasicROSBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageContinueComponentsElemBasicROSBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageContinueComponentsElemBasicROSBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageContinueComponentsElemBasicROSBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageContinueComponentsElemBasicROSBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = TCMessageContinueComponentsElemBasicROSBoundChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec TCMessageContinueComponentsElemBasicROSInvokeBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = TCMessageContinueComponentsElemBasicROSBoundChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = TCMessageContinueComponentsElemBasicROSBoundChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = TCMessageContinueComponentsElemBasicROSBoundChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for TCMessageContinueComponentsElemBasicROSBound CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes TCMessageContinueComponentsElemBound to BER format.
func (v *TCMessageContinueComponentsElemBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageContinueComponentsElemBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageContinueComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.BasicROS.MarshalBER(ber.ChildEncodeOptions(opts, "basicROS")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", false)
		}
		return enc_0, nil
	case TCMessageContinueComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResultNotLast", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageContinueComponentsElemBound", v.Choice)
	}
}

// MarshalDER encodes TCMessageContinueComponentsElemBound to DER format.
func (v *TCMessageContinueComponentsElemBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case TCMessageContinueComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.BasicROS.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "basicROS", "encoding", true)
		}
		return enc_der_0, nil
	case TCMessageContinueComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResultNotLast", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResultNotLast", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageContinueComponentsElemBoundChoiceBasicROS:
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		case TCMessageContinueComponentsElemBoundChoiceReturnResultNotLast:
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageContinueComponentsElemBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageContinueComponentsElemBound from BER/DER format.
func (v *TCMessageContinueComponentsElemBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageContinueComponentsElemBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageContinueComponentsElemBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageContinueComponentsElemBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageContinueComponentsElemBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageContinueComponentsElemBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageContinueComponentsElemBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageContinueComponentsElemBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = TCMessageContinueComponentsElemBoundChoiceReturnResultNotLast
		ber.MarkPreflightTarget(opts, "returnResultNotLast", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResultNotLast", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultNotLast")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResultNotLast", "decoding", false)
		}
		v.ReturnResultNotLast = &dec
	} else {
		v.Choice = TCMessageContinueComponentsElemBoundChoiceBasicROS
		var dec TCMessageContinueComponentsElemBasicROSBound
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "basicROS")...); unmErr != nil {
			return qualifyBERError(unmErr, "basicROS", "decoding", false)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBERTCMessageContinueComponentsBound encodes a TCMessageContinueComponentsBound list to BER.
func MarshalBERTCMessageContinueComponentsBound(collection *TCMessageContinueComponentsBound, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERTCMessageContinueComponentsBound(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERTCMessageContinueComponentsBound(collection *TCMessageContinueComponentsBound, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 12, Constructed: true}, children)
}

// MarshalDERTCMessageContinueComponentsBound encodes a TCMessageContinueComponentsBound list to DER.
func MarshalDERTCMessageContinueComponentsBound(collection *TCMessageContinueComponentsBound) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, encoded)
	if tagErr_encoded != nil {
		return nil, qualifyBERError(tagErr_encoded, "TCMessageContinueComponentsBound", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageContinueComponentsBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERTCMessageContinueComponentsBound decodes a TCMessageContinueComponentsBound list from BER.
func UnmarshalBERTCMessageContinueComponentsBound(data []byte, opts ...ber.DecodeOption) (returnValue *TCMessageContinueComponentsBound, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERTCMessageContinueComponentsBound(data, probeOpts...)
			return probeErr
		})
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding TCMessageContinueComponentsBound", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, fmt.Errorf("%s: %w", "decoding TCMessageContinueComponentsBound", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 12], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TCMessageContinueComponentsBound", Cause: ber.ErrExtraData}
	}
	var result []TCMessageContinueComponentsElemBound
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem TCMessageContinueComponentsElemBound
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	decoded := &TCMessageContinueComponentsBound{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERTCMessageContinueComponentsBound(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes TCMessageContinueBound to BER format.
func (v *TCMessageContinueBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageContinueBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_otid, encodeErr_enc_otid := ber.EncodeOctetString([]byte(v.Otid))
	if encodeErr_enc_otid != nil {
		return nil, qualifyBERError(encodeErr_enc_otid, "otid", "encoding", false)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, qualifyBERError(tagErr_enc_otid, "otid", "encoding", false)
	}
	enc_otid = retagged_enc_otid
	children = append(children, enc_otid...)
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_dtid, encodeErr_enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	if encodeErr_enc_dtid != nil {
		return nil, qualifyBERError(encodeErr_enc_dtid, "dtid", "encoding", false)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, qualifyBERError(tagErr_enc_dtid, "dtid", "encoding", false)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", false)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalBERTCMessageContinueComponentsBound(v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "Components", "encoding", false)
				}
			}
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageContinueBound to DER format.
func (v *TCMessageContinueBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_otid, encodeErr_enc_otid := ber.EncodeOctetString([]byte(v.Otid))
	if encodeErr_enc_otid != nil {
		return nil, qualifyBERError(encodeErr_enc_otid, "otid", "encoding", true)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, qualifyBERError(tagErr_enc_otid, "otid", "encoding", true)
	}
	enc_otid = retagged_enc_otid
	children = append(children, enc_otid...)
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_dtid, encodeErr_enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	if encodeErr_enc_dtid != nil {
		return nil, qualifyBERError(encodeErr_enc_dtid, "dtid", "encoding", true)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, qualifyBERError(tagErr_enc_dtid, "dtid", "encoding", true)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalDERTCMessageContinueComponentsBound(v.Components)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", true)
		}
		children = append(children, enc_components...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageContinueBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageContinueBound from BER/DER format.
func (v *TCMessageContinueBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageContinueBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageContinueBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageContinueBound{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageContinueBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageContinueBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode otid
	if offset >= len(content) {
		return fmt.Errorf("missing required field otid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 8 {
			return fmt.Errorf("expected tag [%s %d] for otid, got %s", "APPLICATION", 8, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "otid", content[offset:])
		decodedTag_otid, n_otid, rawVal_otid, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "otid", "decoding", false)
		}
		if decodedTag_otid.Class != tag.ClassApplication || decodedTag_otid.Number != 8 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_otid), "otid", "decoding", false)
		}
		decVal_otid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_otid.Constructed, rawVal_otid, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "otid", "decoding", false)
		}
		v.Otid = OrigTransactionID(decVal_otid)
		if offset > len(content) || n_otid < 0 || n_otid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_otid
		if len(v.Otid) < 1 || len(v.Otid) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode dtid
	if offset >= len(content) {
		return fmt.Errorf("missing required field dtid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 9 {
			return fmt.Errorf("expected tag [%s %d] for dtid, got %s", "APPLICATION", 9, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "dtid", content[offset:])
		decodedTag_dtid, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "dtid", "decoding", false)
		}
		if decodedTag_dtid.Class != tag.ClassApplication || decodedTag_dtid.Number != 9 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dtid), "dtid", "decoding", false)
		}
		decVal_dtid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_dtid.Constructed, rawVal_dtid, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "dtid", "decoding", false)
		}
		v.Dtid = DestTransactionID(decVal_dtid)
		if offset < 0 || offset >
			len(content) || n_dtid < 0 || n_dtid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_dtid
		if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
			if constraintErr := ber.CheckDecodedLength(opts, "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "dialoguePortion", content[offset:])
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return qualifyBERError(extErr, "dialoguePortion", "decoding", false)
				}
				var decoded_dialogueportion DialoguePortion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if err := decoded_dialogueportion.UnmarshalBER(content[offset:offset+n_dialogueportion], opts...); err != nil {
					return err
				}
				v.DialoguePortion = &decoded_dialogueportion
				if offset < 0 || offset >
					len(content) || n_dialogueportion < 0 || n_dialogueportion > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dialogueportion
			}
		}
	}
	// Decode components
	v.ComponentsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "components", content[offset:])
				// Decode nested SEQUENCE_OF (TCMessageContinueComponentsBound)
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_components != nil {
					return qualifyBERError(tlvErr_components, "components", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_components := content[offset : offset+n_components]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_components)
					if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				dec_components, unmErr := UnmarshalBERTCMessageContinueComponentsBound(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "components", "decoding", false)
				}
				v.Components = dec_components
				if offset < 0 || offset >
					len(content) || n_components < 0 || n_components > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_components
				if len((v.Components).Values) < 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageContinueBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes UnidirectionalComponentsElemBasicROSInvokeBound to BER format.
func (v *UnidirectionalComponentsElemBasicROSInvokeBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnidirectionalComponentsElemBasicROSInvokeBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER(ber.ChildEncodeOptions(opts, "linkedId")...)
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", false)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnidirectionalComponentsElemBasicROSInvokeBound to DER format.
func (v *UnidirectionalComponentsElemBasicROSInvokeBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", true)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		children = append(children, enc_argument...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding UnidirectionalComponentsElemBasicROSInvokeBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes UnidirectionalComponentsElemBasicROSInvokeBound from BER/DER format.
func (v *UnidirectionalComponentsElemBasicROSInvokeBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSInvokeBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe UnidirectionalComponentsElemBasicROSInvokeBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = UnidirectionalComponentsElemBasicROSInvokeBound{}
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
		return fmt.Errorf("%s: %w", "decoding UnidirectionalComponentsElemBasicROSInvokeBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnidirectionalComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (TCInvokeIdSet)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "linkedId", content[offset:])
				// Decode nested CHOICE (UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_linkedid != nil {
					return qualifyBERError(tlvErr_linkedid, "linkedId", "decoding", false)
				}
				var dec_linkedid UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_linkedid.UnmarshalBER(content[offset:offset+n_linkedid], ber.ChildDecodeOptions(opts, "linkedId")...); unmErr != nil {
					return qualifyBERError(unmErr, "linkedId", "decoding", false)
				}
				v.LinkedId = &dec_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode argument
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "argument", content[offset:])
		_, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_argument != nil {
			return qualifyBERError(tlvErr_argument, "argument", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "argument", content[offset:], n_argument)
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_argument := runtime.RawValue{Bytes: content[offset : offset+n_argument]}
		v.Argument = &tmp_argument
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "UnidirectionalComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes UnidirectionalComponentsElemBasicROSBound to BER format.
func (v *UnidirectionalComponentsElemBasicROSBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnidirectionalComponentsElemBasicROSBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case UnidirectionalComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", false)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case UnidirectionalComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResult.MarshalBER(ber.ChildEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResult", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case UnidirectionalComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnError", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case UnidirectionalComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "reject", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for UnidirectionalComponentsElemBasicROSBound", v.Choice)
	}
}

// MarshalDER encodes UnidirectionalComponentsElemBasicROSBound to DER format.
func (v *UnidirectionalComponentsElemBasicROSBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case UnidirectionalComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "invoke", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "invoke", "encoding", true)
		}
		return enc_der_0, nil
	case UnidirectionalComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResult", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResult", "encoding", true)
		}
		return enc_der_1, nil
	case UnidirectionalComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "returnError", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "returnError", "encoding", true)
		}
		return enc_der_2, nil
	case UnidirectionalComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "reject", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "reject", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case UnidirectionalComponentsElemBasicROSBoundChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case UnidirectionalComponentsElemBasicROSBoundChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case UnidirectionalComponentsElemBasicROSBoundChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case UnidirectionalComponentsElemBasicROSBoundChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding UnidirectionalComponentsElemBasicROSBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes UnidirectionalComponentsElemBasicROSBound from BER/DER format.
func (v *UnidirectionalComponentsElemBasicROSBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe UnidirectionalComponentsElemBasicROSBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = UnidirectionalComponentsElemBasicROSBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for UnidirectionalComponentsElemBasicROSBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for UnidirectionalComponentsElemBasicROSBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding UnidirectionalComponentsElemBasicROSBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "UnidirectionalComponentsElemBasicROSBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = UnidirectionalComponentsElemBasicROSBoundChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec UnidirectionalComponentsElemBasicROSInvokeBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = UnidirectionalComponentsElemBasicROSBoundChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = UnidirectionalComponentsElemBasicROSBoundChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = UnidirectionalComponentsElemBasicROSBoundChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for UnidirectionalComponentsElemBasicROSBound CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes UnidirectionalComponentsElemBound to BER format.
func (v *UnidirectionalComponentsElemBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnidirectionalComponentsElemBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case UnidirectionalComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.BasicROS.MarshalBER(ber.ChildEncodeOptions(opts, "basicROS")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", false)
		}
		return enc_0, nil
	case UnidirectionalComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResultNotLast", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for UnidirectionalComponentsElemBound", v.Choice)
	}
}

// MarshalDER encodes UnidirectionalComponentsElemBound to DER format.
func (v *UnidirectionalComponentsElemBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case UnidirectionalComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.BasicROS.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "basicROS", "encoding", true)
		}
		return enc_der_0, nil
	case UnidirectionalComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResultNotLast", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResultNotLast", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case UnidirectionalComponentsElemBoundChoiceBasicROS:
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		case UnidirectionalComponentsElemBoundChoiceReturnResultNotLast:
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding UnidirectionalComponentsElemBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes UnidirectionalComponentsElemBound from BER/DER format.
func (v *UnidirectionalComponentsElemBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnidirectionalComponentsElemBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe UnidirectionalComponentsElemBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = UnidirectionalComponentsElemBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for UnidirectionalComponentsElemBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for UnidirectionalComponentsElemBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding UnidirectionalComponentsElemBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "UnidirectionalComponentsElemBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = UnidirectionalComponentsElemBoundChoiceReturnResultNotLast
		ber.MarkPreflightTarget(opts, "returnResultNotLast", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResultNotLast", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultNotLast")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResultNotLast", "decoding", false)
		}
		v.ReturnResultNotLast = &dec
	} else {
		v.Choice = UnidirectionalComponentsElemBoundChoiceBasicROS
		var dec UnidirectionalComponentsElemBasicROSBound
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "basicROS")...); unmErr != nil {
			return qualifyBERError(unmErr, "basicROS", "decoding", false)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBERUnidirectionalComponentsBound encodes a UnidirectionalComponentsBound list to BER.
func MarshalBERUnidirectionalComponentsBound(collection *UnidirectionalComponentsBound, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERUnidirectionalComponentsBound(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERUnidirectionalComponentsBound(collection *UnidirectionalComponentsBound, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 12, Constructed: true}, children)
}

// MarshalDERUnidirectionalComponentsBound encodes a UnidirectionalComponentsBound list to DER.
func MarshalDERUnidirectionalComponentsBound(collection *UnidirectionalComponentsBound) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, encoded)
	if tagErr_encoded != nil {
		return nil, qualifyBERError(tagErr_encoded, "UnidirectionalComponentsBound", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding UnidirectionalComponentsBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERUnidirectionalComponentsBound decodes a UnidirectionalComponentsBound list from BER.
func UnmarshalBERUnidirectionalComponentsBound(data []byte, opts ...ber.DecodeOption) (returnValue *UnidirectionalComponentsBound, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERUnidirectionalComponentsBound(data, probeOpts...)
			return probeErr
		})
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding UnidirectionalComponentsBound", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, fmt.Errorf("%s: %w", "decoding UnidirectionalComponentsBound", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 12], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "UnidirectionalComponentsBound", Cause: ber.ErrExtraData}
	}
	var result []UnidirectionalComponentsElemBound
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem UnidirectionalComponentsElemBound
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	decoded := &UnidirectionalComponentsBound{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERUnidirectionalComponentsBound(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes BeginComponentsElemBasicROSInvokeBound to BER format.
func (v *BeginComponentsElemBasicROSInvokeBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BeginComponentsElemBasicROSInvokeBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER(ber.ChildEncodeOptions(opts, "linkedId")...)
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", false)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes BeginComponentsElemBasicROSInvokeBound to DER format.
func (v *BeginComponentsElemBasicROSInvokeBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", true)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		children = append(children, enc_argument...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding BeginComponentsElemBasicROSInvokeBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes BeginComponentsElemBasicROSInvokeBound from BER/DER format.
func (v *BeginComponentsElemBasicROSInvokeBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BeginComponentsElemBasicROSInvokeBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe BeginComponentsElemBasicROSInvokeBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = BeginComponentsElemBasicROSInvokeBound{}
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
		return fmt.Errorf("%s: %w", "decoding BeginComponentsElemBasicROSInvokeBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BeginComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (TCInvokeIdSet)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "linkedId", content[offset:])
				// Decode nested CHOICE (BeginComponentsElemBasicROSInvokeBoundLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_linkedid != nil {
					return qualifyBERError(tlvErr_linkedid, "linkedId", "decoding", false)
				}
				var dec_linkedid BeginComponentsElemBasicROSInvokeBoundLinkedId
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_linkedid.UnmarshalBER(content[offset:offset+n_linkedid], ber.ChildDecodeOptions(opts, "linkedId")...); unmErr != nil {
					return qualifyBERError(unmErr, "linkedId", "decoding", false)
				}
				v.LinkedId = &dec_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode argument
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "argument", content[offset:])
		_, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_argument != nil {
			return qualifyBERError(tlvErr_argument, "argument", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "argument", content[offset:], n_argument)
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_argument := runtime.RawValue{Bytes: content[offset : offset+n_argument]}
		v.Argument = &tmp_argument
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "BeginComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes BeginComponentsElemBasicROSBound to BER format.
func (v *BeginComponentsElemBasicROSBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BeginComponentsElemBasicROSBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case BeginComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", false)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case BeginComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResult.MarshalBER(ber.ChildEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResult", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case BeginComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnError", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case BeginComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "reject", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for BeginComponentsElemBasicROSBound", v.Choice)
	}
}

// MarshalDER encodes BeginComponentsElemBasicROSBound to DER format.
func (v *BeginComponentsElemBasicROSBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case BeginComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "invoke", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "invoke", "encoding", true)
		}
		return enc_der_0, nil
	case BeginComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResult", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResult", "encoding", true)
		}
		return enc_der_1, nil
	case BeginComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "returnError", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "returnError", "encoding", true)
		}
		return enc_der_2, nil
	case BeginComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "reject", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "reject", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case BeginComponentsElemBasicROSBoundChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case BeginComponentsElemBasicROSBoundChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case BeginComponentsElemBasicROSBoundChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case BeginComponentsElemBasicROSBoundChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding BeginComponentsElemBasicROSBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes BeginComponentsElemBasicROSBound from BER/DER format.
func (v *BeginComponentsElemBasicROSBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BeginComponentsElemBasicROSBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe BeginComponentsElemBasicROSBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = BeginComponentsElemBasicROSBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for BeginComponentsElemBasicROSBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for BeginComponentsElemBasicROSBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding BeginComponentsElemBasicROSBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "BeginComponentsElemBasicROSBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = BeginComponentsElemBasicROSBoundChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec BeginComponentsElemBasicROSInvokeBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = BeginComponentsElemBasicROSBoundChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = BeginComponentsElemBasicROSBoundChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = BeginComponentsElemBasicROSBoundChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for BeginComponentsElemBasicROSBound CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes BeginComponentsElemBound to BER format.
func (v *BeginComponentsElemBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BeginComponentsElemBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case BeginComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.BasicROS.MarshalBER(ber.ChildEncodeOptions(opts, "basicROS")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", false)
		}
		return enc_0, nil
	case BeginComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResultNotLast", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for BeginComponentsElemBound", v.Choice)
	}
}

// MarshalDER encodes BeginComponentsElemBound to DER format.
func (v *BeginComponentsElemBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case BeginComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.BasicROS.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "basicROS", "encoding", true)
		}
		return enc_der_0, nil
	case BeginComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResultNotLast", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResultNotLast", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case BeginComponentsElemBoundChoiceBasicROS:
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		case BeginComponentsElemBoundChoiceReturnResultNotLast:
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding BeginComponentsElemBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes BeginComponentsElemBound from BER/DER format.
func (v *BeginComponentsElemBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BeginComponentsElemBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe BeginComponentsElemBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = BeginComponentsElemBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for BeginComponentsElemBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for BeginComponentsElemBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding BeginComponentsElemBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "BeginComponentsElemBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = BeginComponentsElemBoundChoiceReturnResultNotLast
		ber.MarkPreflightTarget(opts, "returnResultNotLast", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResultNotLast", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultNotLast")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResultNotLast", "decoding", false)
		}
		v.ReturnResultNotLast = &dec
	} else {
		v.Choice = BeginComponentsElemBoundChoiceBasicROS
		var dec BeginComponentsElemBasicROSBound
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "basicROS")...); unmErr != nil {
			return qualifyBERError(unmErr, "basicROS", "decoding", false)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBERBeginComponentsBound encodes a BeginComponentsBound list to BER.
func MarshalBERBeginComponentsBound(collection *BeginComponentsBound, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERBeginComponentsBound(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERBeginComponentsBound(collection *BeginComponentsBound, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 12, Constructed: true}, children)
}

// MarshalDERBeginComponentsBound encodes a BeginComponentsBound list to DER.
func MarshalDERBeginComponentsBound(collection *BeginComponentsBound) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, encoded)
	if tagErr_encoded != nil {
		return nil, qualifyBERError(tagErr_encoded, "BeginComponentsBound", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding BeginComponentsBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERBeginComponentsBound decodes a BeginComponentsBound list from BER.
func UnmarshalBERBeginComponentsBound(data []byte, opts ...ber.DecodeOption) (returnValue *BeginComponentsBound, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERBeginComponentsBound(data, probeOpts...)
			return probeErr
		})
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding BeginComponentsBound", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, fmt.Errorf("%s: %w", "decoding BeginComponentsBound", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 12], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BeginComponentsBound", Cause: ber.ErrExtraData}
	}
	var result []BeginComponentsElemBound
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem BeginComponentsElemBound
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	decoded := &BeginComponentsBound{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERBeginComponentsBound(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes EndComponentsElemBasicROSInvokeBound to BER format.
func (v *EndComponentsElemBasicROSInvokeBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EndComponentsElemBasicROSInvokeBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER(ber.ChildEncodeOptions(opts, "linkedId")...)
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", false)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes EndComponentsElemBasicROSInvokeBound to DER format.
func (v *EndComponentsElemBasicROSInvokeBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", true)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		children = append(children, enc_argument...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding EndComponentsElemBasicROSInvokeBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes EndComponentsElemBasicROSInvokeBound from BER/DER format.
func (v *EndComponentsElemBasicROSInvokeBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EndComponentsElemBasicROSInvokeBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe EndComponentsElemBasicROSInvokeBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = EndComponentsElemBasicROSInvokeBound{}
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
		return fmt.Errorf("%s: %w", "decoding EndComponentsElemBasicROSInvokeBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EndComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (TCInvokeIdSet)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "linkedId", content[offset:])
				// Decode nested CHOICE (EndComponentsElemBasicROSInvokeBoundLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_linkedid != nil {
					return qualifyBERError(tlvErr_linkedid, "linkedId", "decoding", false)
				}
				var dec_linkedid EndComponentsElemBasicROSInvokeBoundLinkedId
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_linkedid.UnmarshalBER(content[offset:offset+n_linkedid], ber.ChildDecodeOptions(opts, "linkedId")...); unmErr != nil {
					return qualifyBERError(unmErr, "linkedId", "decoding", false)
				}
				v.LinkedId = &dec_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode argument
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "argument", content[offset:])
		_, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_argument != nil {
			return qualifyBERError(tlvErr_argument, "argument", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "argument", content[offset:], n_argument)
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_argument := runtime.RawValue{Bytes: content[offset : offset+n_argument]}
		v.Argument = &tmp_argument
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EndComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EndComponentsElemBasicROSBound to BER format.
func (v *EndComponentsElemBasicROSBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EndComponentsElemBasicROSBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case EndComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", false)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case EndComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResult.MarshalBER(ber.ChildEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResult", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case EndComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnError", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case EndComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "reject", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EndComponentsElemBasicROSBound", v.Choice)
	}
}

// MarshalDER encodes EndComponentsElemBasicROSBound to DER format.
func (v *EndComponentsElemBasicROSBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case EndComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "invoke", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "invoke", "encoding", true)
		}
		return enc_der_0, nil
	case EndComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResult", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResult", "encoding", true)
		}
		return enc_der_1, nil
	case EndComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "returnError", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "returnError", "encoding", true)
		}
		return enc_der_2, nil
	case EndComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "reject", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "reject", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case EndComponentsElemBasicROSBoundChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case EndComponentsElemBasicROSBoundChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case EndComponentsElemBasicROSBoundChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case EndComponentsElemBasicROSBoundChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding EndComponentsElemBasicROSBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes EndComponentsElemBasicROSBound from BER/DER format.
func (v *EndComponentsElemBasicROSBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EndComponentsElemBasicROSBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe EndComponentsElemBasicROSBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = EndComponentsElemBasicROSBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for EndComponentsElemBasicROSBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EndComponentsElemBasicROSBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding EndComponentsElemBasicROSBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EndComponentsElemBasicROSBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = EndComponentsElemBasicROSBoundChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec EndComponentsElemBasicROSInvokeBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = EndComponentsElemBasicROSBoundChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = EndComponentsElemBasicROSBoundChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = EndComponentsElemBasicROSBoundChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for EndComponentsElemBasicROSBound CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EndComponentsElemBound to BER format.
func (v *EndComponentsElemBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EndComponentsElemBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case EndComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.BasicROS.MarshalBER(ber.ChildEncodeOptions(opts, "basicROS")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", false)
		}
		return enc_0, nil
	case EndComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResultNotLast", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EndComponentsElemBound", v.Choice)
	}
}

// MarshalDER encodes EndComponentsElemBound to DER format.
func (v *EndComponentsElemBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case EndComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.BasicROS.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "basicROS", "encoding", true)
		}
		return enc_der_0, nil
	case EndComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResultNotLast", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResultNotLast", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case EndComponentsElemBoundChoiceBasicROS:
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		case EndComponentsElemBoundChoiceReturnResultNotLast:
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding EndComponentsElemBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes EndComponentsElemBound from BER/DER format.
func (v *EndComponentsElemBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EndComponentsElemBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe EndComponentsElemBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = EndComponentsElemBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for EndComponentsElemBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EndComponentsElemBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding EndComponentsElemBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EndComponentsElemBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = EndComponentsElemBoundChoiceReturnResultNotLast
		ber.MarkPreflightTarget(opts, "returnResultNotLast", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResultNotLast", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultNotLast")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResultNotLast", "decoding", false)
		}
		v.ReturnResultNotLast = &dec
	} else {
		v.Choice = EndComponentsElemBoundChoiceBasicROS
		var dec EndComponentsElemBasicROSBound
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "basicROS")...); unmErr != nil {
			return qualifyBERError(unmErr, "basicROS", "decoding", false)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBEREndComponentsBound encodes a EndComponentsBound list to BER.
func MarshalBEREndComponentsBound(collection *EndComponentsBound, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBEREndComponentsBound(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBEREndComponentsBound(collection *EndComponentsBound, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 12, Constructed: true}, children)
}

// MarshalDEREndComponentsBound encodes a EndComponentsBound list to DER.
func MarshalDEREndComponentsBound(collection *EndComponentsBound) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, encoded)
	if tagErr_encoded != nil {
		return nil, qualifyBERError(tagErr_encoded, "EndComponentsBound", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding EndComponentsBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBEREndComponentsBound decodes a EndComponentsBound list from BER.
func UnmarshalBEREndComponentsBound(data []byte, opts ...ber.DecodeOption) (returnValue *EndComponentsBound, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBEREndComponentsBound(data, probeOpts...)
			return probeErr
		})
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding EndComponentsBound", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, fmt.Errorf("%s: %w", "decoding EndComponentsBound", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 12], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "EndComponentsBound", Cause: ber.ErrExtraData}
	}
	var result []EndComponentsElemBound
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem EndComponentsElemBound
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	decoded := &EndComponentsBound{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBEREndComponentsBound(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes ContinueComponentsElemBasicROSInvokeBound to BER format.
func (v *ContinueComponentsElemBasicROSInvokeBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ContinueComponentsElemBasicROSInvokeBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER(ber.ChildEncodeOptions(opts, "linkedId")...)
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", false)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ContinueComponentsElemBasicROSInvokeBound to DER format.
func (v *ContinueComponentsElemBasicROSInvokeBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", true)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		children = append(children, enc_argument...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ContinueComponentsElemBasicROSInvokeBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ContinueComponentsElemBasicROSInvokeBound from BER/DER format.
func (v *ContinueComponentsElemBasicROSInvokeBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ContinueComponentsElemBasicROSInvokeBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ContinueComponentsElemBasicROSInvokeBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ContinueComponentsElemBasicROSInvokeBound{}
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
		return fmt.Errorf("%s: %w", "decoding ContinueComponentsElemBasicROSInvokeBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ContinueComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (TCInvokeIdSet)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "linkedId", content[offset:])
				// Decode nested CHOICE (ContinueComponentsElemBasicROSInvokeBoundLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_linkedid != nil {
					return qualifyBERError(tlvErr_linkedid, "linkedId", "decoding", false)
				}
				var dec_linkedid ContinueComponentsElemBasicROSInvokeBoundLinkedId
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_linkedid.UnmarshalBER(content[offset:offset+n_linkedid], ber.ChildDecodeOptions(opts, "linkedId")...); unmErr != nil {
					return qualifyBERError(unmErr, "linkedId", "decoding", false)
				}
				v.LinkedId = &dec_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode argument
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "argument", content[offset:])
		_, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_argument != nil {
			return qualifyBERError(tlvErr_argument, "argument", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "argument", content[offset:], n_argument)
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_argument := runtime.RawValue{Bytes: content[offset : offset+n_argument]}
		v.Argument = &tmp_argument
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ContinueComponentsElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ContinueComponentsElemBasicROSBound to BER format.
func (v *ContinueComponentsElemBasicROSBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ContinueComponentsElemBasicROSBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ContinueComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", false)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ContinueComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResult.MarshalBER(ber.ChildEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResult", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case ContinueComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnError", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case ContinueComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "reject", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ContinueComponentsElemBasicROSBound", v.Choice)
	}
}

// MarshalDER encodes ContinueComponentsElemBasicROSBound to DER format.
func (v *ContinueComponentsElemBasicROSBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ContinueComponentsElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "invoke", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "invoke", "encoding", true)
		}
		return enc_der_0, nil
	case ContinueComponentsElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResult", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResult", "encoding", true)
		}
		return enc_der_1, nil
	case ContinueComponentsElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "returnError", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "returnError", "encoding", true)
		}
		return enc_der_2, nil
	case ContinueComponentsElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "reject", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "reject", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ContinueComponentsElemBasicROSBoundChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case ContinueComponentsElemBasicROSBoundChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case ContinueComponentsElemBasicROSBoundChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case ContinueComponentsElemBasicROSBoundChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ContinueComponentsElemBasicROSBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ContinueComponentsElemBasicROSBound from BER/DER format.
func (v *ContinueComponentsElemBasicROSBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ContinueComponentsElemBasicROSBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ContinueComponentsElemBasicROSBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ContinueComponentsElemBasicROSBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ContinueComponentsElemBasicROSBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ContinueComponentsElemBasicROSBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ContinueComponentsElemBasicROSBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ContinueComponentsElemBasicROSBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ContinueComponentsElemBasicROSBoundChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ContinueComponentsElemBasicROSInvokeBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ContinueComponentsElemBasicROSBoundChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ContinueComponentsElemBasicROSBoundChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ContinueComponentsElemBasicROSBoundChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ContinueComponentsElemBasicROSBound CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ContinueComponentsElemBound to BER format.
func (v *ContinueComponentsElemBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ContinueComponentsElemBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ContinueComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.BasicROS.MarshalBER(ber.ChildEncodeOptions(opts, "basicROS")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", false)
		}
		return enc_0, nil
	case ContinueComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResultNotLast", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ContinueComponentsElemBound", v.Choice)
	}
}

// MarshalDER encodes ContinueComponentsElemBound to DER format.
func (v *ContinueComponentsElemBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ContinueComponentsElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.BasicROS.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "basicROS", "encoding", true)
		}
		return enc_der_0, nil
	case ContinueComponentsElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResultNotLast", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResultNotLast", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ContinueComponentsElemBoundChoiceBasicROS:
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		case ContinueComponentsElemBoundChoiceReturnResultNotLast:
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ContinueComponentsElemBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ContinueComponentsElemBound from BER/DER format.
func (v *ContinueComponentsElemBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ContinueComponentsElemBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ContinueComponentsElemBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ContinueComponentsElemBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ContinueComponentsElemBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ContinueComponentsElemBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ContinueComponentsElemBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ContinueComponentsElemBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = ContinueComponentsElemBoundChoiceReturnResultNotLast
		ber.MarkPreflightTarget(opts, "returnResultNotLast", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResultNotLast", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultNotLast")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResultNotLast", "decoding", false)
		}
		v.ReturnResultNotLast = &dec
	} else {
		v.Choice = ContinueComponentsElemBoundChoiceBasicROS
		var dec ContinueComponentsElemBasicROSBound
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "basicROS")...); unmErr != nil {
			return qualifyBERError(unmErr, "basicROS", "decoding", false)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBERContinueComponentsBound encodes a ContinueComponentsBound list to BER.
func MarshalBERContinueComponentsBound(collection *ContinueComponentsBound, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERContinueComponentsBound(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERContinueComponentsBound(collection *ContinueComponentsBound, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 12, Constructed: true}, children)
}

// MarshalDERContinueComponentsBound encodes a ContinueComponentsBound list to DER.
func MarshalDERContinueComponentsBound(collection *ContinueComponentsBound) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
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
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, encoded)
	if tagErr_encoded != nil {
		return nil, qualifyBERError(tagErr_encoded, "ContinueComponentsBound", "encoding", true)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ContinueComponentsBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBERContinueComponentsBound decodes a ContinueComponentsBound list from BER.
func UnmarshalBERContinueComponentsBound(data []byte, opts ...ber.DecodeOption) (returnValue *ContinueComponentsBound, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, ber.DiagnosePreflight(err, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERContinueComponentsBound(data, probeOpts...)
			return probeErr
		})
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding ContinueComponentsBound", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, fmt.Errorf("%s: %w", "decoding ContinueComponentsBound", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 12], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ContinueComponentsBound", Cause: ber.ErrExtraData}
	}
	var result []ContinueComponentsElemBound
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem ContinueComponentsElemBound
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
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
	decoded := &ContinueComponentsBound{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERContinueComponentsBound(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes ComponentPortionElemBasicROSInvokeBound to BER format.
func (v *ComponentPortionElemBasicROSInvokeBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentPortionElemBasicROSInvokeBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER(ber.ChildEncodeOptions(opts, "linkedId")...)
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", false)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ComponentPortionElemBasicROSInvokeBound to DER format.
func (v *ComponentPortionElemBasicROSInvokeBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", true)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		children = append(children, enc_argument...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ComponentPortionElemBasicROSInvokeBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentPortionElemBasicROSInvokeBound from BER/DER format.
func (v *ComponentPortionElemBasicROSInvokeBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentPortionElemBasicROSInvokeBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ComponentPortionElemBasicROSInvokeBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ComponentPortionElemBasicROSInvokeBound{}
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
		return fmt.Errorf("%s: %w", "decoding ComponentPortionElemBasicROSInvokeBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentPortionElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (TCInvokeIdSet)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "linkedId", content[offset:])
				// Decode nested CHOICE (ComponentPortionElemBasicROSInvokeBoundLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_linkedid != nil {
					return qualifyBERError(tlvErr_linkedid, "linkedId", "decoding", false)
				}
				var dec_linkedid ComponentPortionElemBasicROSInvokeBoundLinkedId
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_linkedid.UnmarshalBER(content[offset:offset+n_linkedid], ber.ChildDecodeOptions(opts, "linkedId")...); unmErr != nil {
					return qualifyBERError(unmErr, "linkedId", "decoding", false)
				}
				v.LinkedId = &dec_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode argument
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "argument", content[offset:])
		_, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_argument != nil {
			return qualifyBERError(tlvErr_argument, "argument", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "argument", content[offset:], n_argument)
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_argument := runtime.RawValue{Bytes: content[offset : offset+n_argument]}
		v.Argument = &tmp_argument
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ComponentPortionElemBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ComponentPortionElemBasicROSBound to BER format.
func (v *ComponentPortionElemBasicROSBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentPortionElemBasicROSBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ComponentPortionElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", false)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ComponentPortionElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResult.MarshalBER(ber.ChildEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResult", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case ComponentPortionElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnError", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case ComponentPortionElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "reject", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ComponentPortionElemBasicROSBound", v.Choice)
	}
}

// MarshalDER encodes ComponentPortionElemBasicROSBound to DER format.
func (v *ComponentPortionElemBasicROSBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ComponentPortionElemBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "invoke", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "invoke", "encoding", true)
		}
		return enc_der_0, nil
	case ComponentPortionElemBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResult", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResult", "encoding", true)
		}
		return enc_der_1, nil
	case ComponentPortionElemBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "returnError", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "returnError", "encoding", true)
		}
		return enc_der_2, nil
	case ComponentPortionElemBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "reject", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "reject", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ComponentPortionElemBasicROSBoundChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case ComponentPortionElemBasicROSBoundChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case ComponentPortionElemBasicROSBoundChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case ComponentPortionElemBasicROSBoundChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ComponentPortionElemBasicROSBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentPortionElemBasicROSBound from BER/DER format.
func (v *ComponentPortionElemBasicROSBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentPortionElemBasicROSBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ComponentPortionElemBasicROSBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ComponentPortionElemBasicROSBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ComponentPortionElemBasicROSBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ComponentPortionElemBasicROSBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ComponentPortionElemBasicROSBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentPortionElemBasicROSBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ComponentPortionElemBasicROSBoundChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ComponentPortionElemBasicROSInvokeBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ComponentPortionElemBasicROSBoundChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ComponentPortionElemBasicROSBoundChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ComponentPortionElemBasicROSBoundChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ComponentPortionElemBasicROSBound CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ComponentPortionElemBound to BER format.
func (v *ComponentPortionElemBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentPortionElemBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ComponentPortionElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.BasicROS.MarshalBER(ber.ChildEncodeOptions(opts, "basicROS")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", false)
		}
		return enc_0, nil
	case ComponentPortionElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER(ber.ChildEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResultNotLast", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ComponentPortionElemBound", v.Choice)
	}
}

// MarshalDER encodes ComponentPortionElemBound to DER format.
func (v *ComponentPortionElemBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ComponentPortionElemBoundChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBound: basicROS is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.BasicROS.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "basicROS", "encoding", true)
		}
		return enc_der_0, nil
	case ComponentPortionElemBoundChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBound: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResultNotLast", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResultNotLast", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ComponentPortionElemBoundChoiceBasicROS:
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		case ComponentPortionElemBoundChoiceReturnResultNotLast:
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ComponentPortionElemBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentPortionElemBound from BER/DER format.
func (v *ComponentPortionElemBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentPortionElemBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ComponentPortionElemBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ComponentPortionElemBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ComponentPortionElemBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ComponentPortionElemBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ComponentPortionElemBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentPortionElemBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = ComponentPortionElemBoundChoiceReturnResultNotLast
		ber.MarkPreflightTarget(opts, "returnResultNotLast", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResultNotLast", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResultNotLast")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResultNotLast", "decoding", false)
		}
		v.ReturnResultNotLast = &dec
	} else {
		v.Choice = ComponentPortionElemBoundChoiceBasicROS
		var dec ComponentPortionElemBasicROSBound
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "basicROS")...); unmErr != nil {
			return qualifyBERError(unmErr, "basicROS", "decoding", false)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBER encodes ComponentBasicROSInvokeBound to BER format.
func (v *ComponentBasicROSInvokeBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentBasicROSInvokeBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalBER(ber.ChildEncodeOptions(opts, "invokeId")...)
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", false)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalBER(ber.ChildEncodeOptions(opts, "linkedId")...)
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", false)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, qualifyBERError(err, "argument", "encoding", false)
		}
		if rawErr := ber.ValidateBEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", false)
		}
		children = append(children, enc_argument...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ComponentBasicROSInvokeBound to DER format.
func (v *ComponentBasicROSInvokeBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSInvokeBound receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_invokeid, err := v.InvokeId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "invokeId", "encoding", true)
	}
	children = append(children, enc_invokeid...)
	if v.LinkedId != nil {
		enc_linkedid, err := v.LinkedId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "linkedId", "encoding", true)
		}
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if v.Argument != nil {
		enc_argument := v.Argument.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_argument); rawErr != nil {
			return nil, qualifyBERError(rawErr, "argument", "encoding", true)
		}
		children = append(children, enc_argument...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ComponentBasicROSInvokeBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentBasicROSInvokeBound from BER/DER format.
func (v *ComponentBasicROSInvokeBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentBasicROSInvokeBound destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ComponentBasicROSInvokeBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ComponentBasicROSInvokeBound{}
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
		return fmt.Errorf("%s: %w", "decoding ComponentBasicROSInvokeBound SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeId
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeId")
	}
	{
		ber.MarkPreflightTarget(opts, "invokeId", content[offset:])
		// Decode nested CHOICE (TCInvokeIdSet)
		_, n_invokeid, _, tlvErr_invokeid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_invokeid != nil {
			return qualifyBERError(tlvErr_invokeid, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.InvokeId.UnmarshalBER(content[offset:offset+n_invokeid], ber.ChildDecodeOptions(opts, "invokeId")...); unmErr != nil {
			return qualifyBERError(unmErr, "invokeId", "decoding", false)
		}
		if offset > len(content) || n_invokeid < 0 || n_invokeid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_invokeid
	}
	// Decode linkedId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "linkedId", content[offset:])
				// Decode nested CHOICE (ComponentBasicROSInvokeBoundLinkedId)
				_, n_linkedid, _, tlvErr_linkedid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_linkedid != nil {
					return qualifyBERError(tlvErr_linkedid, "linkedId", "decoding", false)
				}
				var dec_linkedid ComponentBasicROSInvokeBoundLinkedId
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_linkedid.UnmarshalBER(content[offset:offset+n_linkedid], ber.ChildDecodeOptions(opts, "linkedId")...); unmErr != nil {
					return qualifyBERError(unmErr, "linkedId", "decoding", false)
				}
				v.LinkedId = &dec_linkedid
				if offset < 0 || offset >
					len(content) || n_linkedid < 0 || n_linkedid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_linkedid
			}
		}
	}
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode argument
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "argument", content[offset:])
		_, n_argument, _, tlvErr_argument := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_argument != nil {
			return qualifyBERError(tlvErr_argument, "argument", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "argument", content[offset:], n_argument)
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_argument := runtime.RawValue{Bytes: content[offset : offset+n_argument]}
		v.Argument = &tmp_argument
		if offset < 0 || offset >
			len(content) || n_argument < 0 || n_argument > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_argument
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ComponentBasicROSInvokeBound", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ComponentBasicROSBound to BER format.
func (v *ComponentBasicROSBound) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentBasicROSBound) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ComponentBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ComponentBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Invoke.MarshalBER(ber.ChildEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", false)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "invoke", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ComponentBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ComponentBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResult.MarshalBER(ber.ChildEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "returnResult", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case ComponentBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ComponentBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.ReturnError.MarshalBER(ber.ChildEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "returnError", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case ComponentBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ComponentBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Reject.MarshalBER(ber.ChildEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "reject", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ComponentBasicROSBound", v.Choice)
	}
}

// MarshalDER encodes ComponentBasicROSBound to DER format.
func (v *ComponentBasicROSBound) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSBound receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ComponentBasicROSBoundChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ComponentBasicROSBound: invoke is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "invoke", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "invoke", "encoding", true)
		}
		return enc_der_0, nil
	case ComponentBasicROSBoundChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ComponentBasicROSBound: returnResult is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "returnResult", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "returnResult", "encoding", true)
		}
		return enc_der_1, nil
	case ComponentBasicROSBoundChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ComponentBasicROSBound: returnError is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "returnError", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "returnError", "encoding", true)
		}
		return enc_der_2, nil
	case ComponentBasicROSBoundChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ComponentBasicROSBound: reject is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "reject", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "reject", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ComponentBasicROSBoundChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case ComponentBasicROSBoundChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case ComponentBasicROSBoundChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case ComponentBasicROSBoundChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ComponentBasicROSBound as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentBasicROSBound from BER/DER format.
func (v *ComponentBasicROSBound) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentBasicROSBound destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ComponentBasicROSBound
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ComponentBasicROSBound{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ComponentBasicROSBound CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ComponentBasicROSBound: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ComponentBasicROSBound CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentBasicROSBound", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ComponentBasicROSBoundChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ComponentBasicROSInvokeBound
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ComponentBasicROSBoundChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ComponentBasicROSBoundChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ComponentBasicROSBoundChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ComponentBasicROSBound CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AbortReason to BER format.
func (v *AbortReason) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AbortReason receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AbortReason) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case AbortReasonChoicePAbortCause:
		if v.PAbortCause == nil {
			return nil, fmt.Errorf("%w: choice AbortReason: p-abortCause is nil", ber.ErrInvalidValue)
		}
		enc_0 := ber.EncodeInteger(int64(*v.PAbortCause))
		if !(int64(*v.PAbortCause) >= 0 && int64(*v.PAbortCause) <= 127) {
			if constraintErr := ber.CheckEncodedValue(opts, "p-abortCause", "(0..127)", fmt.Sprint(int64(*v.PAbortCause))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 10, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "p-abortCause", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case AbortReasonChoiceUAbortCause:
		if v.UAbortCause == nil {
			return nil, fmt.Errorf("%w: choice AbortReason: u-abortCause is nil", ber.ErrInvalidValue)
		}
		enc_1, extErr := v.UAbortCause.MarshalBER(ber.ChildEncodeOptions(opts, "u-abortCause")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "u-abortCause", "encoding", false)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AbortReason", v.Choice)
	}
}

// MarshalDER encodes AbortReason to DER format.
func (v *AbortReason) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AbortReason receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case AbortReasonChoiceUAbortCause:
		if v.UAbortCause == nil {
			return nil, fmt.Errorf("%w: choice AbortReason: u-abortCause is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.UAbortCause.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "u-abortCause", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "u-abortCause", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case AbortReasonChoicePAbortCause:
			return nil, qualifyBERError(err, "p-abortCause", "encoding", true)
		case AbortReasonChoiceUAbortCause:
			return nil, qualifyBERError(err, "u-abortCause", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding AbortReason as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes AbortReason from BER/DER format.
func (v *AbortReason) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AbortReason destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AbortReason
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = AbortReason{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for AbortReason CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AbortReason: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding AbortReason CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AbortReason", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 10 && peekTag.Constructed == false {
		v.Choice = AbortReasonChoicePAbortCause
		ber.MarkPreflightTarget(opts, "p-abortCause", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "p-abortCause", "decoding", false)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "p-abortCause", "decoding", false)
		}
		tmp := PAbortCause(decVal)
		v.PAbortCause = &tmp
		if !(int64(*v.PAbortCause) >= 0 && int64(*v.PAbortCause) <= 127) {
			if constraintErr := ber.CheckDecodedValue(opts, "p-abortCause", "(0..127)", fmt.Sprint(int64(*v.PAbortCause))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 && peekTag.Constructed == true {
		v.Choice = AbortReasonChoiceUAbortCause
		ber.MarkPreflightTarget(opts, "u-abortCause", choiceData)
		var decodedExternal DialoguePortion
		if err := decodedExternal.UnmarshalBER(choiceData, opts...); err != nil {
			return err
		}
		v.UAbortCause = &decodedExternal
	} else {
		return fmt.Errorf("unknown tag %s for AbortReason CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ComponentReturnResultNotLastResult to BER format.
func (v *ComponentReturnResultNotLastResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentReturnResultNotLastResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ComponentReturnResultNotLastResult to DER format.
func (v *ComponentReturnResultNotLastResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ComponentReturnResultNotLastResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentReturnResultNotLastResult from BER/DER format.
func (v *ComponentReturnResultNotLastResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentReturnResultNotLastResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ComponentReturnResultNotLastResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ComponentReturnResultNotLastResult{}
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
		return fmt.Errorf("%s: %w", "decoding ComponentReturnResultNotLastResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ComponentReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId to BER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId", v.Choice)
	}
}

// MarshalDER encodes TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId to DER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId from BER/DER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for TCMessageUnidirectionalComponentsElemBasicROSInvokeBoundLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult to BER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult to DER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult from BER/DER format.
func (v *TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageUnidirectionalComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult to BER format.
func (v *TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult to DER format.
func (v *TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult from BER/DER format.
func (v *TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageUnidirectionalComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId to BER format.
func (v *TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId", v.Choice)
	}
}

// MarshalDER encodes TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId to DER format.
func (v *TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId from BER/DER format.
func (v *TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for TCMessageBeginComponentsElemBasicROSInvokeBoundLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes TCMessageBeginComponentsElemBasicROSBoundReturnResultResult to BER format.
func (v *TCMessageBeginComponentsElemBasicROSBoundReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageBeginComponentsElemBasicROSBoundReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageBeginComponentsElemBasicROSBoundReturnResultResult to DER format.
func (v *TCMessageBeginComponentsElemBasicROSBoundReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageBeginComponentsElemBasicROSBoundReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageBeginComponentsElemBasicROSBoundReturnResultResult from BER/DER format.
func (v *TCMessageBeginComponentsElemBasicROSBoundReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageBeginComponentsElemBasicROSBoundReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageBeginComponentsElemBasicROSBoundReturnResultResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageBeginComponentsElemBasicROSBoundReturnResultResult{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageBeginComponentsElemBasicROSBoundReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageBeginComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageBeginComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageBeginComponentsElemBoundReturnResultNotLastResult to BER format.
func (v *TCMessageBeginComponentsElemBoundReturnResultNotLastResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageBeginComponentsElemBoundReturnResultNotLastResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageBeginComponentsElemBoundReturnResultNotLastResult to DER format.
func (v *TCMessageBeginComponentsElemBoundReturnResultNotLastResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageBeginComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageBeginComponentsElemBoundReturnResultNotLastResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageBeginComponentsElemBoundReturnResultNotLastResult from BER/DER format.
func (v *TCMessageBeginComponentsElemBoundReturnResultNotLastResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageBeginComponentsElemBoundReturnResultNotLastResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageBeginComponentsElemBoundReturnResultNotLastResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageBeginComponentsElemBoundReturnResultNotLastResult{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageBeginComponentsElemBoundReturnResultNotLastResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageBeginComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageBeginComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId to BER format.
func (v *TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case TCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId", v.Choice)
	}
}

// MarshalDER encodes TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId to DER format.
func (v *TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case TCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId from BER/DER format.
func (v *TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = TCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = TCMessageEndComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for TCMessageEndComponentsElemBasicROSInvokeBoundLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes TCMessageEndComponentsElemBasicROSBoundReturnResultResult to BER format.
func (v *TCMessageEndComponentsElemBasicROSBoundReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageEndComponentsElemBasicROSBoundReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageEndComponentsElemBasicROSBoundReturnResultResult to DER format.
func (v *TCMessageEndComponentsElemBasicROSBoundReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageEndComponentsElemBasicROSBoundReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageEndComponentsElemBasicROSBoundReturnResultResult from BER/DER format.
func (v *TCMessageEndComponentsElemBasicROSBoundReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageEndComponentsElemBasicROSBoundReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageEndComponentsElemBasicROSBoundReturnResultResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageEndComponentsElemBasicROSBoundReturnResultResult{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageEndComponentsElemBasicROSBoundReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageEndComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageEndComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageEndComponentsElemBoundReturnResultNotLastResult to BER format.
func (v *TCMessageEndComponentsElemBoundReturnResultNotLastResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageEndComponentsElemBoundReturnResultNotLastResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageEndComponentsElemBoundReturnResultNotLastResult to DER format.
func (v *TCMessageEndComponentsElemBoundReturnResultNotLastResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageEndComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageEndComponentsElemBoundReturnResultNotLastResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageEndComponentsElemBoundReturnResultNotLastResult from BER/DER format.
func (v *TCMessageEndComponentsElemBoundReturnResultNotLastResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageEndComponentsElemBoundReturnResultNotLastResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageEndComponentsElemBoundReturnResultNotLastResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageEndComponentsElemBoundReturnResultNotLastResult{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageEndComponentsElemBoundReturnResultNotLastResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageEndComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageEndComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId to BER format.
func (v *TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId", v.Choice)
	}
}

// MarshalDER encodes TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId to DER format.
func (v *TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId from BER/DER format.
func (v *TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for TCMessageContinueComponentsElemBasicROSInvokeBoundLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes TCMessageContinueComponentsElemBasicROSBoundReturnResultResult to BER format.
func (v *TCMessageContinueComponentsElemBasicROSBoundReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageContinueComponentsElemBasicROSBoundReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageContinueComponentsElemBasicROSBoundReturnResultResult to DER format.
func (v *TCMessageContinueComponentsElemBasicROSBoundReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageContinueComponentsElemBasicROSBoundReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageContinueComponentsElemBasicROSBoundReturnResultResult from BER/DER format.
func (v *TCMessageContinueComponentsElemBasicROSBoundReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageContinueComponentsElemBasicROSBoundReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageContinueComponentsElemBasicROSBoundReturnResultResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageContinueComponentsElemBasicROSBoundReturnResultResult{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageContinueComponentsElemBasicROSBoundReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageContinueComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageContinueComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessageContinueComponentsElemBoundReturnResultNotLastResult to BER format.
func (v *TCMessageContinueComponentsElemBoundReturnResultNotLastResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *TCMessageContinueComponentsElemBoundReturnResultNotLastResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes TCMessageContinueComponentsElemBoundReturnResultNotLastResult to DER format.
func (v *TCMessageContinueComponentsElemBoundReturnResultNotLastResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessageContinueComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TCMessageContinueComponentsElemBoundReturnResultNotLastResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessageContinueComponentsElemBoundReturnResultNotLastResult from BER/DER format.
func (v *TCMessageContinueComponentsElemBoundReturnResultNotLastResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessageContinueComponentsElemBoundReturnResultNotLastResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessageContinueComponentsElemBoundReturnResultNotLastResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = TCMessageContinueComponentsElemBoundReturnResultNotLastResult{}
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
		return fmt.Errorf("%s: %w", "decoding TCMessageContinueComponentsElemBoundReturnResultNotLastResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessageContinueComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TCMessageContinueComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId to BER format.
func (v *UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case UnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case UnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId", v.Choice)
	}
}

// MarshalDER encodes UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId to DER format.
func (v *UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case UnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case UnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId from BER/DER format.
func (v *UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = UnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = UnidirectionalComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for UnidirectionalComponentsElemBasicROSInvokeBoundLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes UnidirectionalComponentsElemBasicROSBoundReturnResultResult to BER format.
func (v *UnidirectionalComponentsElemBasicROSBoundReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnidirectionalComponentsElemBasicROSBoundReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnidirectionalComponentsElemBasicROSBoundReturnResultResult to DER format.
func (v *UnidirectionalComponentsElemBasicROSBoundReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding UnidirectionalComponentsElemBasicROSBoundReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes UnidirectionalComponentsElemBasicROSBoundReturnResultResult from BER/DER format.
func (v *UnidirectionalComponentsElemBasicROSBoundReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnidirectionalComponentsElemBasicROSBoundReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe UnidirectionalComponentsElemBasicROSBoundReturnResultResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = UnidirectionalComponentsElemBasicROSBoundReturnResultResult{}
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
		return fmt.Errorf("%s: %w", "decoding UnidirectionalComponentsElemBasicROSBoundReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnidirectionalComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "UnidirectionalComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes UnidirectionalComponentsElemBoundReturnResultNotLastResult to BER format.
func (v *UnidirectionalComponentsElemBoundReturnResultNotLastResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UnidirectionalComponentsElemBoundReturnResultNotLastResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UnidirectionalComponentsElemBoundReturnResultNotLastResult to DER format.
func (v *UnidirectionalComponentsElemBoundReturnResultNotLastResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UnidirectionalComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding UnidirectionalComponentsElemBoundReturnResultNotLastResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes UnidirectionalComponentsElemBoundReturnResultNotLastResult from BER/DER format.
func (v *UnidirectionalComponentsElemBoundReturnResultNotLastResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UnidirectionalComponentsElemBoundReturnResultNotLastResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe UnidirectionalComponentsElemBoundReturnResultNotLastResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = UnidirectionalComponentsElemBoundReturnResultNotLastResult{}
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
		return fmt.Errorf("%s: %w", "decoding UnidirectionalComponentsElemBoundReturnResultNotLastResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UnidirectionalComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "UnidirectionalComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes BeginComponentsElemBasicROSInvokeBoundLinkedId to BER format.
func (v *BeginComponentsElemBasicROSInvokeBoundLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BeginComponentsElemBasicROSInvokeBoundLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case BeginComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice BeginComponentsElemBasicROSInvokeBoundLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case BeginComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for BeginComponentsElemBasicROSInvokeBoundLinkedId", v.Choice)
	}
}

// MarshalDER encodes BeginComponentsElemBasicROSInvokeBoundLinkedId to DER format.
func (v *BeginComponentsElemBasicROSInvokeBoundLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case BeginComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case BeginComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding BeginComponentsElemBasicROSInvokeBoundLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes BeginComponentsElemBasicROSInvokeBoundLinkedId from BER/DER format.
func (v *BeginComponentsElemBasicROSInvokeBoundLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BeginComponentsElemBasicROSInvokeBoundLinkedId destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe BeginComponentsElemBasicROSInvokeBoundLinkedId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = BeginComponentsElemBasicROSInvokeBoundLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for BeginComponentsElemBasicROSInvokeBoundLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for BeginComponentsElemBasicROSInvokeBoundLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding BeginComponentsElemBasicROSInvokeBoundLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "BeginComponentsElemBasicROSInvokeBoundLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = BeginComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = BeginComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for BeginComponentsElemBasicROSInvokeBoundLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes BeginComponentsElemBasicROSBoundReturnResultResult to BER format.
func (v *BeginComponentsElemBasicROSBoundReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BeginComponentsElemBasicROSBoundReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes BeginComponentsElemBasicROSBoundReturnResultResult to DER format.
func (v *BeginComponentsElemBasicROSBoundReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding BeginComponentsElemBasicROSBoundReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes BeginComponentsElemBasicROSBoundReturnResultResult from BER/DER format.
func (v *BeginComponentsElemBasicROSBoundReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BeginComponentsElemBasicROSBoundReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe BeginComponentsElemBasicROSBoundReturnResultResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = BeginComponentsElemBasicROSBoundReturnResultResult{}
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
		return fmt.Errorf("%s: %w", "decoding BeginComponentsElemBasicROSBoundReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BeginComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "BeginComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes BeginComponentsElemBoundReturnResultNotLastResult to BER format.
func (v *BeginComponentsElemBoundReturnResultNotLastResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *BeginComponentsElemBoundReturnResultNotLastResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes BeginComponentsElemBoundReturnResultNotLastResult to DER format.
func (v *BeginComponentsElemBoundReturnResultNotLastResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BeginComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding BeginComponentsElemBoundReturnResultNotLastResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes BeginComponentsElemBoundReturnResultNotLastResult from BER/DER format.
func (v *BeginComponentsElemBoundReturnResultNotLastResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: BeginComponentsElemBoundReturnResultNotLastResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe BeginComponentsElemBoundReturnResultNotLastResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = BeginComponentsElemBoundReturnResultNotLastResult{}
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
		return fmt.Errorf("%s: %w", "decoding BeginComponentsElemBoundReturnResultNotLastResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BeginComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "BeginComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EndComponentsElemBasicROSInvokeBoundLinkedId to BER format.
func (v *EndComponentsElemBasicROSInvokeBoundLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EndComponentsElemBasicROSInvokeBoundLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case EndComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice EndComponentsElemBasicROSInvokeBoundLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case EndComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for EndComponentsElemBasicROSInvokeBoundLinkedId", v.Choice)
	}
}

// MarshalDER encodes EndComponentsElemBasicROSInvokeBoundLinkedId to DER format.
func (v *EndComponentsElemBasicROSInvokeBoundLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case EndComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case EndComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding EndComponentsElemBasicROSInvokeBoundLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes EndComponentsElemBasicROSInvokeBoundLinkedId from BER/DER format.
func (v *EndComponentsElemBasicROSInvokeBoundLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EndComponentsElemBasicROSInvokeBoundLinkedId destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe EndComponentsElemBasicROSInvokeBoundLinkedId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = EndComponentsElemBasicROSInvokeBoundLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for EndComponentsElemBasicROSInvokeBoundLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for EndComponentsElemBasicROSInvokeBoundLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding EndComponentsElemBasicROSInvokeBoundLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "EndComponentsElemBasicROSInvokeBoundLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = EndComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = EndComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for EndComponentsElemBasicROSInvokeBoundLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes EndComponentsElemBasicROSBoundReturnResultResult to BER format.
func (v *EndComponentsElemBasicROSBoundReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EndComponentsElemBasicROSBoundReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes EndComponentsElemBasicROSBoundReturnResultResult to DER format.
func (v *EndComponentsElemBasicROSBoundReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding EndComponentsElemBasicROSBoundReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes EndComponentsElemBasicROSBoundReturnResultResult from BER/DER format.
func (v *EndComponentsElemBasicROSBoundReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EndComponentsElemBasicROSBoundReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe EndComponentsElemBasicROSBoundReturnResultResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = EndComponentsElemBasicROSBoundReturnResultResult{}
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
		return fmt.Errorf("%s: %w", "decoding EndComponentsElemBasicROSBoundReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EndComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EndComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes EndComponentsElemBoundReturnResultNotLastResult to BER format.
func (v *EndComponentsElemBoundReturnResultNotLastResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EndComponentsElemBoundReturnResultNotLastResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes EndComponentsElemBoundReturnResultNotLastResult to DER format.
func (v *EndComponentsElemBoundReturnResultNotLastResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EndComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding EndComponentsElemBoundReturnResultNotLastResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes EndComponentsElemBoundReturnResultNotLastResult from BER/DER format.
func (v *EndComponentsElemBoundReturnResultNotLastResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EndComponentsElemBoundReturnResultNotLastResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe EndComponentsElemBoundReturnResultNotLastResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = EndComponentsElemBoundReturnResultNotLastResult{}
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
		return fmt.Errorf("%s: %w", "decoding EndComponentsElemBoundReturnResultNotLastResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EndComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EndComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ContinueComponentsElemBasicROSInvokeBoundLinkedId to BER format.
func (v *ContinueComponentsElemBasicROSInvokeBoundLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ContinueComponentsElemBasicROSInvokeBoundLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ContinueComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice ContinueComponentsElemBasicROSInvokeBoundLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ContinueComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ContinueComponentsElemBasicROSInvokeBoundLinkedId", v.Choice)
	}
}

// MarshalDER encodes ContinueComponentsElemBasicROSInvokeBoundLinkedId to DER format.
func (v *ContinueComponentsElemBasicROSInvokeBoundLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ContinueComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case ContinueComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ContinueComponentsElemBasicROSInvokeBoundLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ContinueComponentsElemBasicROSInvokeBoundLinkedId from BER/DER format.
func (v *ContinueComponentsElemBasicROSInvokeBoundLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ContinueComponentsElemBasicROSInvokeBoundLinkedId destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ContinueComponentsElemBasicROSInvokeBoundLinkedId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ContinueComponentsElemBasicROSInvokeBoundLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ContinueComponentsElemBasicROSInvokeBoundLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ContinueComponentsElemBasicROSInvokeBoundLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ContinueComponentsElemBasicROSInvokeBoundLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ContinueComponentsElemBasicROSInvokeBoundLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ContinueComponentsElemBasicROSInvokeBoundLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = ContinueComponentsElemBasicROSInvokeBoundLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for ContinueComponentsElemBasicROSInvokeBoundLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ContinueComponentsElemBasicROSBoundReturnResultResult to BER format.
func (v *ContinueComponentsElemBasicROSBoundReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ContinueComponentsElemBasicROSBoundReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ContinueComponentsElemBasicROSBoundReturnResultResult to DER format.
func (v *ContinueComponentsElemBasicROSBoundReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ContinueComponentsElemBasicROSBoundReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ContinueComponentsElemBasicROSBoundReturnResultResult from BER/DER format.
func (v *ContinueComponentsElemBasicROSBoundReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ContinueComponentsElemBasicROSBoundReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ContinueComponentsElemBasicROSBoundReturnResultResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ContinueComponentsElemBasicROSBoundReturnResultResult{}
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
		return fmt.Errorf("%s: %w", "decoding ContinueComponentsElemBasicROSBoundReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ContinueComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ContinueComponentsElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ContinueComponentsElemBoundReturnResultNotLastResult to BER format.
func (v *ContinueComponentsElemBoundReturnResultNotLastResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ContinueComponentsElemBoundReturnResultNotLastResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ContinueComponentsElemBoundReturnResultNotLastResult to DER format.
func (v *ContinueComponentsElemBoundReturnResultNotLastResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ContinueComponentsElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ContinueComponentsElemBoundReturnResultNotLastResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ContinueComponentsElemBoundReturnResultNotLastResult from BER/DER format.
func (v *ContinueComponentsElemBoundReturnResultNotLastResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ContinueComponentsElemBoundReturnResultNotLastResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ContinueComponentsElemBoundReturnResultNotLastResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ContinueComponentsElemBoundReturnResultNotLastResult{}
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
		return fmt.Errorf("%s: %w", "decoding ContinueComponentsElemBoundReturnResultNotLastResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ContinueComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ContinueComponentsElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ComponentPortionElemBasicROSInvokeBoundLinkedId to BER format.
func (v *ComponentPortionElemBasicROSInvokeBoundLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentPortionElemBasicROSInvokeBoundLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ComponentPortionElemBasicROSInvokeBoundLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice ComponentPortionElemBasicROSInvokeBoundLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ComponentPortionElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ComponentPortionElemBasicROSInvokeBoundLinkedId", v.Choice)
	}
}

// MarshalDER encodes ComponentPortionElemBasicROSInvokeBoundLinkedId to DER format.
func (v *ComponentPortionElemBasicROSInvokeBoundLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ComponentPortionElemBasicROSInvokeBoundLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case ComponentPortionElemBasicROSInvokeBoundLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ComponentPortionElemBasicROSInvokeBoundLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentPortionElemBasicROSInvokeBoundLinkedId from BER/DER format.
func (v *ComponentPortionElemBasicROSInvokeBoundLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentPortionElemBasicROSInvokeBoundLinkedId destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ComponentPortionElemBasicROSInvokeBoundLinkedId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ComponentPortionElemBasicROSInvokeBoundLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ComponentPortionElemBasicROSInvokeBoundLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ComponentPortionElemBasicROSInvokeBoundLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ComponentPortionElemBasicROSInvokeBoundLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentPortionElemBasicROSInvokeBoundLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ComponentPortionElemBasicROSInvokeBoundLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = ComponentPortionElemBasicROSInvokeBoundLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for ComponentPortionElemBasicROSInvokeBoundLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ComponentPortionElemBasicROSBoundReturnResultResult to BER format.
func (v *ComponentPortionElemBasicROSBoundReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentPortionElemBasicROSBoundReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ComponentPortionElemBasicROSBoundReturnResultResult to DER format.
func (v *ComponentPortionElemBasicROSBoundReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ComponentPortionElemBasicROSBoundReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentPortionElemBasicROSBoundReturnResultResult from BER/DER format.
func (v *ComponentPortionElemBasicROSBoundReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentPortionElemBasicROSBoundReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ComponentPortionElemBasicROSBoundReturnResultResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ComponentPortionElemBasicROSBoundReturnResultResult{}
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
		return fmt.Errorf("%s: %w", "decoding ComponentPortionElemBasicROSBoundReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentPortionElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ComponentPortionElemBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ComponentPortionElemBoundReturnResultNotLastResult to BER format.
func (v *ComponentPortionElemBoundReturnResultNotLastResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentPortionElemBoundReturnResultNotLastResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ComponentPortionElemBoundReturnResultNotLastResult to DER format.
func (v *ComponentPortionElemBoundReturnResultNotLastResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentPortionElemBoundReturnResultNotLastResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ComponentPortionElemBoundReturnResultNotLastResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentPortionElemBoundReturnResultNotLastResult from BER/DER format.
func (v *ComponentPortionElemBoundReturnResultNotLastResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentPortionElemBoundReturnResultNotLastResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ComponentPortionElemBoundReturnResultNotLastResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ComponentPortionElemBoundReturnResultNotLastResult{}
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
		return fmt.Errorf("%s: %w", "decoding ComponentPortionElemBoundReturnResultNotLastResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentPortionElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ComponentPortionElemBoundReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ComponentBasicROSInvokeBoundLinkedId to BER format.
func (v *ComponentBasicROSInvokeBoundLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentBasicROSInvokeBoundLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ComponentBasicROSInvokeBoundLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice ComponentBasicROSInvokeBoundLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "present", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ComponentBasicROSInvokeBoundLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ComponentBasicROSInvokeBoundLinkedId", v.Choice)
	}
}

// MarshalDER encodes ComponentBasicROSInvokeBoundLinkedId to DER format.
func (v *ComponentBasicROSInvokeBoundLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSInvokeBoundLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ComponentBasicROSInvokeBoundLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case ComponentBasicROSInvokeBoundLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ComponentBasicROSInvokeBoundLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentBasicROSInvokeBoundLinkedId from BER/DER format.
func (v *ComponentBasicROSInvokeBoundLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentBasicROSInvokeBoundLinkedId destination is nil", ber.ErrInvalidValue)
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
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ComponentBasicROSInvokeBoundLinkedId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ComponentBasicROSInvokeBoundLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ComponentBasicROSInvokeBoundLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ComponentBasicROSInvokeBoundLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ComponentBasicROSInvokeBoundLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentBasicROSInvokeBoundLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ComponentBasicROSInvokeBoundLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = ComponentBasicROSInvokeBoundLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for ComponentBasicROSInvokeBoundLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ComponentBasicROSBoundReturnResultResult to BER format.
func (v *ComponentBasicROSBoundReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentBasicROSBoundReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	if rawErr := ber.ValidateBEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ComponentBasicROSBoundReturnResultResult to DER format.
func (v *ComponentBasicROSBoundReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSBoundReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ComponentBasicROSBoundReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentBasicROSBoundReturnResultResult from BER/DER format.
func (v *ComponentBasicROSBoundReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentBasicROSBoundReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return ber.DiagnosePreflight(err, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ComponentBasicROSBoundReturnResultResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	*v = ComponentBasicROSBoundReturnResultResult{}
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
		return fmt.Errorf("%s: %w", "decoding ComponentBasicROSBoundReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	{
		ber.MarkPreflightTarget(opts, "opcode", content[offset:])
		// Decode nested CHOICE (Code)
		_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_opcode != nil {
			return qualifyBERError(tlvErr_opcode, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
			return qualifyBERError(unmErr, "opcode", "decoding", false)
		}
		if offset > len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_opcode
	}
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ComponentBasicROSBoundReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}
