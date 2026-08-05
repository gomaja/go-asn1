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

// ExternalPDU represents the ASN.1 type ExternalPDU (SEQUENCE).
type ExternalPDU struct {
	Oid    runtime.ObjectIdentifier `asn1:""`
	Dialog Dialog1                  `asn1:"tag:0,context,implicit"`
}

// Dialog1 represents the ASN.1 type Dialog1 (OCTET_STRING).
type Dialog1 = []byte

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
	Unidirectional *Unidirectional `json:"Unidirectional,omitempty"`
	Begin          *Begin          `json:"Begin,omitempty"`
	End            *End            `json:"End,omitempty"`
	Continue       *Continue       `json:"Continue,omitempty"`
	Abort          *Abort          `json:"Abort,omitempty"`
}

// NewTCMessageUnidirectional creates a TCMessage with the unidirectional alternative.
func NewTCMessageUnidirectional(v Unidirectional) TCMessage {
	return TCMessage{
		Choice:         TCMessageChoiceUnidirectional,
		Unidirectional: &v,
	}
}

// NewTCMessageBegin creates a TCMessage with the begin alternative.
func NewTCMessageBegin(v Begin) TCMessage {
	return TCMessage{
		Choice: TCMessageChoiceBegin,
		Begin:  &v,
	}
}

// NewTCMessageEnd creates a TCMessage with the end alternative.
func NewTCMessageEnd(v End) TCMessage {
	return TCMessage{
		Choice: TCMessageChoiceEnd,
		End:    &v,
	}
}

// NewTCMessageContinue creates a TCMessage with the continue alternative.
func NewTCMessageContinue(v Continue) TCMessage {
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
	DialoguePortion  *DialoguePortion `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       ComponentPortion `asn1:""`
	ComponentsIndef_ bool             `asn1:"-" json:"-"`
}

// Begin represents the ASN.1 type Begin (SEQUENCE).
type Begin struct {
	Otid             OrigTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       ComponentPortion  `asn1:",optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
}

// End represents the ASN.1 type End (SEQUENCE).
type End struct {
	Dtid             DestTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       ComponentPortion  `asn1:",optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
}

// Continue represents the ASN.1 type Continue (SEQUENCE).
type Continue struct {
	Otid             OrigTransactionID `asn1:""`
	Dtid             DestTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       ComponentPortion  `asn1:",optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
}

// Abort represents the ASN.1 type Abort (SEQUENCE).
type Abort struct {
	Dtid   DestTransactionID `asn1:""`
	Reason *Reason           `asn1:",optional" json:"Reason,omitempty"`
}

// Reason choice constants.
const (
	ReasonChoicePAbortCause = 1
	ReasonChoiceUAbortCause = 2
)

// Reason represents the ASN.1 CHOICE type Reason.
type Reason struct {
	Choice      int
	PAbortCause *PAbortCause     `json:"PAbortCause,omitempty"`
	UAbortCause *DialoguePortion `json:"UAbortCause,omitempty"`
}

// NewReasonPAbortCause creates a Reason with the p-abortCause alternative.
func NewReasonPAbortCause(v PAbortCause) Reason {
	return Reason{
		Choice:      ReasonChoicePAbortCause,
		PAbortCause: &v,
	}
}

// NewReasonUAbortCause creates a Reason with the u-abortCause alternative.
func NewReasonUAbortCause(v DialoguePortion) Reason {
	return Reason{
		Choice:      ReasonChoiceUAbortCause,
		UAbortCause: &v,
	}
}

// DialoguePortion represents the ASN.1 type DialoguePortion (OCTET_STRING).
type DialoguePortion = []byte

// DialogueOC represents the ASN.1 type DialogueOC (OCTET_STRING).
type DialogueOC = []byte

// OrigTransactionID represents the ASN.1 type OrigTransactionID (OCTET_STRING).
type OrigTransactionID = []byte

// DestTransactionID represents the ASN.1 type DestTransactionID (OCTET_STRING).
type DestTransactionID = []byte

// PAbortCause represents the ASN.1 INTEGER type P-AbortCause with named numbers.
type PAbortCause = int64

const (
	PAbortCauseUnrecognizedMessageType          PAbortCause = 0
	PAbortCauseUnrecognizedTransactionID        PAbortCause = 1
	PAbortCauseBadlyFormattedTransactionPortion PAbortCause = 2
	PAbortCauseIncorrectTransactionPortion      PAbortCause = 3
	PAbortCauseResourceLimitation               PAbortCause = 4
)

// ComponentPortion represents the ASN.1 type ComponentPortion (SEQUENCE_OF).
type ComponentPortion = []Component

// Component choice constants.
const (
	ComponentChoiceInvoke              = 1
	ComponentChoiceReturnResultLast    = 2
	ComponentChoiceReturnError         = 3
	ComponentChoiceReject              = 4
	ComponentChoiceReturnResultNotLast = 5
)

// Component represents the ASN.1 CHOICE type Component.
type Component struct {
	Choice              int
	Invoke              *Invoke       `json:"Invoke,omitempty"`
	ReturnResultLast    *ReturnResult `json:"ReturnResultLast,omitempty"`
	ReturnError         *ReturnError  `json:"ReturnError,omitempty"`
	Reject              *Reject       `json:"Reject,omitempty"`
	ReturnResultNotLast *ReturnResult `json:"ReturnResultNotLast,omitempty"`
}

// NewComponentInvoke creates a Component with the invoke alternative.
func NewComponentInvoke(v Invoke) Component {
	return Component{
		Choice: ComponentChoiceInvoke,
		Invoke: &v,
	}
}

// NewComponentReturnResultLast creates a Component with the returnResultLast alternative.
func NewComponentReturnResultLast(v ReturnResult) Component {
	return Component{
		Choice:           ComponentChoiceReturnResultLast,
		ReturnResultLast: &v,
	}
}

// NewComponentReturnError creates a Component with the returnError alternative.
func NewComponentReturnError(v ReturnError) Component {
	return Component{
		Choice:      ComponentChoiceReturnError,
		ReturnError: &v,
	}
}

// NewComponentReject creates a Component with the reject alternative.
func NewComponentReject(v Reject) Component {
	return Component{
		Choice: ComponentChoiceReject,
		Reject: &v,
	}
}

// NewComponentReturnResultNotLast creates a Component with the returnResultNotLast alternative.
func NewComponentReturnResultNotLast(v ReturnResult) Component {
	return Component{
		Choice:              ComponentChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// Invoke represents the ASN.1 type Invoke (SEQUENCE).
type Invoke struct {
	InvokeID  InvokeIdType      `asn1:""`
	LinkedID  *InvokeIdType     `asn1:"tag:0,context,implicit,optional" json:"LinkedID,omitempty"`
	OpCode    OPERATION         `asn1:""`
	Parameter *runtime.RawValue `asn1:",optional" json:"Parameter,omitempty"`
}

// Parameter represents the ASN.1 type Parameter (ANY).
type Parameter = runtime.RawValue

// ReturnResult represents the ASN.1 type ReturnResult (SEQUENCE).
type ReturnResult struct {
	InvokeID     InvokeIdType              `asn1:""`
	Resultretres *ReturnResultResultretres `asn1:",optional" json:"Resultretres,omitempty"`
}

// ReturnError represents the ASN.1 type ReturnError (SEQUENCE).
type ReturnError struct {
	InvokeID  InvokeIdType      `asn1:""`
	ErrorCode ErrorCode         `asn1:""`
	Parameter *runtime.RawValue `asn1:",optional" json:"Parameter,omitempty"`
}

// Reject represents the ASN.1 type Reject (SEQUENCE).
type Reject struct {
	InvokeIDRej RejectInvokeIDRej `asn1:""`
	Problem     RejectProblem     `asn1:""`
}

// InvokeIdType represents the ASN.1 type InvokeIdType (INTEGER).
type InvokeIdType = int64

// OPERATION choice constants.
const (
	OPERATIONChoiceLocalValue  = 1
	OPERATIONChoiceGlobalValue = 2
)

// OPERATION represents the ASN.1 CHOICE type OPERATION.
type OPERATION struct {
	Choice      int
	LocalValue  *big.Int                 `json:"LocalValue,omitempty"`
	GlobalValue runtime.ObjectIdentifier `json:"GlobalValue,omitempty"`
}

// NewOPERATIONLocalValue creates a OPERATION with the localValue alternative.
func NewOPERATIONLocalValue(v *big.Int) OPERATION {
	return OPERATION{
		Choice:     OPERATIONChoiceLocalValue,
		LocalValue: v,
	}
}

// NewOPERATIONGlobalValue creates a OPERATION with the globalValue alternative.
func NewOPERATIONGlobalValue(v runtime.ObjectIdentifier) OPERATION {
	return OPERATION{
		Choice:      OPERATIONChoiceGlobalValue,
		GlobalValue: v,
	}
}

// ERROR choice constants.
const (
	ERRORChoiceLocalValue  = 1
	ERRORChoiceGlobalValue = 2
)

// ERROR represents the ASN.1 CHOICE type ERROR.
type ERROR struct {
	Choice      int
	LocalValue  *big.Int                 `json:"LocalValue,omitempty"`
	GlobalValue runtime.ObjectIdentifier `json:"GlobalValue,omitempty"`
}

// NewERRORLocalValue creates a ERROR with the localValue alternative.
func NewERRORLocalValue(v *big.Int) ERROR {
	return ERROR{
		Choice:     ERRORChoiceLocalValue,
		LocalValue: v,
	}
}

// NewERRORGlobalValue creates a ERROR with the globalValue alternative.
func NewERRORGlobalValue(v runtime.ObjectIdentifier) ERROR {
	return ERROR{
		Choice:      ERRORChoiceGlobalValue,
		GlobalValue: v,
	}
}

// GeneralProblem represents the ASN.1 INTEGER type GeneralProblem with named numbers.
type GeneralProblem = int64

const (
	GeneralProblemUnrecognizedComponent    GeneralProblem = 0
	GeneralProblemMistypedComponent        GeneralProblem = 1
	GeneralProblemBadlyStructuredComponent GeneralProblem = 2
)

// InvokeProblem represents the ASN.1 INTEGER type InvokeProblem with named numbers.
type InvokeProblem = int64

const (
	InvokeProblemDuplicateInvokeID         InvokeProblem = 0
	InvokeProblemUnrecognizedOperation     InvokeProblem = 1
	InvokeProblemMistypedParameter         InvokeProblem = 2
	InvokeProblemResourceLimitation        InvokeProblem = 3
	InvokeProblemInitiatingRelease         InvokeProblem = 4
	InvokeProblemUnrecognizedLinkedID      InvokeProblem = 5
	InvokeProblemLinkedResponseUnexpected  InvokeProblem = 6
	InvokeProblemUnexpectedLinkedOperation InvokeProblem = 7
)

// ReturnResultProblem represents the ASN.1 INTEGER type ReturnResultProblem with named numbers.
type ReturnResultProblem = int64

const (
	ReturnResultProblemUnrecognizedInvokeID   ReturnResultProblem = 0
	ReturnResultProblemReturnResultUnexpected ReturnResultProblem = 1
	ReturnResultProblemMistypedParameter      ReturnResultProblem = 2
)

// ReturnErrorProblem represents the ASN.1 INTEGER type ReturnErrorProblem with named numbers.
type ReturnErrorProblem = int64

const (
	ReturnErrorProblemUnrecognizedInvokeID  ReturnErrorProblem = 0
	ReturnErrorProblemReturnErrorUnexpected ReturnErrorProblem = 1
	ReturnErrorProblemUnrecognizedError     ReturnErrorProblem = 2
	ReturnErrorProblemUnexpectedError       ReturnErrorProblem = 3
	ReturnErrorProblemMistypedParameter     ReturnErrorProblem = 4
)

// ErrorCode choice constants.
const (
	ErrorCodeChoiceNationaler = 1
	ErrorCodeChoicePrivateer  = 2
)

// ErrorCode represents the ASN.1 CHOICE type ErrorCode.
type ErrorCode struct {
	Choice     int
	Nationaler *int64   `json:"Nationaler,omitempty"`
	Privateer  *big.Int `json:"Privateer,omitempty"`
}

// NewErrorCodeNationaler creates a ErrorCode with the nationaler alternative.
func NewErrorCodeNationaler(v int64) ErrorCode {
	return ErrorCode{
		Choice:     ErrorCodeChoiceNationaler,
		Nationaler: &v,
	}
}

// NewErrorCodePrivateer creates a ErrorCode with the privateer alternative.
func NewErrorCodePrivateer(v *big.Int) ErrorCode {
	return ErrorCode{
		Choice:    ErrorCodeChoicePrivateer,
		Privateer: v,
	}
}

// ReturnResultResultretres represents the ASN.1 type ReturnResult-resultretres (SEQUENCE).
type ReturnResultResultretres struct {
	OpCode    OPERATION         `asn1:""`
	Parameter *runtime.RawValue `asn1:",optional" json:"Parameter,omitempty"`
}

// RejectInvokeIDRej choice constants.
const (
	RejectInvokeIDRejChoiceDerivable    = 1
	RejectInvokeIDRejChoiceNotDerivable = 2
)

// RejectInvokeIDRej represents the ASN.1 CHOICE type Reject-invokeIDRej.
type RejectInvokeIDRej struct {
	Choice       int
	Derivable    *InvokeIdType `json:"Derivable,omitempty"`
	NotDerivable *struct{}     `json:"NotDerivable,omitempty"`
}

// NewRejectInvokeIDRejDerivable creates a Reject-invokeIDRej with the derivable alternative.
func NewRejectInvokeIDRejDerivable(v InvokeIdType) RejectInvokeIDRej {
	return RejectInvokeIDRej{
		Choice:    RejectInvokeIDRejChoiceDerivable,
		Derivable: &v,
	}
}

// NewRejectInvokeIDRejNotDerivable creates a Reject-invokeIDRej with the not-derivable alternative.
func NewRejectInvokeIDRejNotDerivable(v struct{}) RejectInvokeIDRej {
	return RejectInvokeIDRej{
		Choice:       RejectInvokeIDRejChoiceNotDerivable,
		NotDerivable: &v,
	}
}

// RejectProblem choice constants.
const (
	RejectProblemChoiceGeneralProblem      = 1
	RejectProblemChoiceInvokeProblem       = 2
	RejectProblemChoiceReturnResultProblem = 3
	RejectProblemChoiceReturnErrorProblem  = 4
)

// RejectProblem represents the ASN.1 CHOICE type Reject-problem.
type RejectProblem struct {
	Choice              int
	GeneralProblem      *GeneralProblem      `json:"GeneralProblem,omitempty"`
	InvokeProblem       *InvokeProblem       `json:"InvokeProblem,omitempty"`
	ReturnResultProblem *ReturnResultProblem `json:"ReturnResultProblem,omitempty"`
	ReturnErrorProblem  *ReturnErrorProblem  `json:"ReturnErrorProblem,omitempty"`
}

// NewRejectProblemGeneralProblem creates a Reject-problem with the generalProblem alternative.
func NewRejectProblemGeneralProblem(v GeneralProblem) RejectProblem {
	return RejectProblem{
		Choice:         RejectProblemChoiceGeneralProblem,
		GeneralProblem: &v,
	}
}

// NewRejectProblemInvokeProblem creates a Reject-problem with the invokeProblem alternative.
func NewRejectProblemInvokeProblem(v InvokeProblem) RejectProblem {
	return RejectProblem{
		Choice:        RejectProblemChoiceInvokeProblem,
		InvokeProblem: &v,
	}
}

// NewRejectProblemReturnResultProblem creates a Reject-problem with the returnResultProblem alternative.
func NewRejectProblemReturnResultProblem(v ReturnResultProblem) RejectProblem {
	return RejectProblem{
		Choice:              RejectProblemChoiceReturnResultProblem,
		ReturnResultProblem: &v,
	}
}

// NewRejectProblemReturnErrorProblem creates a Reject-problem with the returnErrorProblem alternative.
func NewRejectProblemReturnErrorProblem(v ReturnErrorProblem) RejectProblem {
	return RejectProblem{
		Choice:             RejectProblemChoiceReturnErrorProblem,
		ReturnErrorProblem: &v,
	}
}

// MarshalBER encodes ExternalPDU to BER format.
func (v *ExternalPDU) MarshalBER() ([]byte, error) {
	var children []byte
	enc_oid := ber.EncodeObjectIdentifier([]uint64(v.Oid))
	children = append(children, enc_oid...)
	enc_dialog := ber.EncodeOctetString([]byte(v.Dialog))
	enc_dialog = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_dialog)
	children = append(children, enc_dialog...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassUniversal, Number: 8, Constructed: true}, children), nil
}

// MarshalDER encodes ExternalPDU to DER format.
func (v *ExternalPDU) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ExternalPDU from BER/DER format.
func (v *ExternalPDU) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExternalPDU: %w", err)
	}
	if decodedTag.Class != tag.ClassUniversal || decodedTag.Number != 8 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ExternalPDU: %w: expected tag [UNIVERSAL 8], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExternalPDU", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode oid
	if offset >= len(content) {
		return fmt.Errorf("missing required field oid")
	}
	val_oid, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding oid: %w", err)
	}
	v.Oid = runtime.ObjectIdentifier(val_oid)
	offset += n
	// Decode dialog
	if offset >= len(content) {
		return fmt.Errorf("missing required field dialog")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for dialog, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_dialog, rawVal_dialog, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dialog: %w", err)
	}
	v.Dialog = Dialog1(rawVal_dialog)
	offset += n_dialog
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExternalPDU", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes TCMessage to BER format.
func (v *TCMessage) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case TCMessageChoiceUnidirectional:
		if v.Unidirectional == nil {
			return nil, fmt.Errorf("choice TCMessage: unidirectional is nil")
		}
		enc_0, err := v.Unidirectional.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding unidirectional: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 1, true, enc_0)
		return enc_0, nil
	case TCMessageChoiceBegin:
		if v.Begin == nil {
			return nil, fmt.Errorf("choice TCMessage: begin is nil")
		}
		enc_1, err := v.Begin.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding begin: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 2, true, enc_1)
		return enc_1, nil
	case TCMessageChoiceEnd:
		if v.End == nil {
			return nil, fmt.Errorf("choice TCMessage: end is nil")
		}
		enc_2, err := v.End.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding end: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 4, true, enc_2)
		return enc_2, nil
	case TCMessageChoiceContinue:
		if v.Continue == nil {
			return nil, fmt.Errorf("choice TCMessage: continue is nil")
		}
		enc_3, err := v.Continue.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding continue: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 5, true, enc_3)
		return enc_3, nil
	case TCMessageChoiceAbort:
		if v.Abort == nil {
			return nil, fmt.Errorf("choice TCMessage: abort is nil")
		}
		enc_4, err := v.Abort.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding abort: %w", err)
		}
		enc_4 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 7, true, enc_4)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for TCMessage", v.Choice)
	}
}

// MarshalDER encodes TCMessage to DER format.
func (v *TCMessage) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes TCMessage from BER/DER format.
func (v *TCMessage) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessage CHOICE")
	}
	peekTag, peekErr := ber.PeekTag(data)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessage: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(data)
	if tlvErr != nil {
		return fmt.Errorf("decoding TCMessage CHOICE: %w", tlvErr)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessage", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 1 {
		v.Choice = TCMessageChoiceUnidirectional
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding unidirectional: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Unidirectional
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding unidirectional: %w", unmErr)
		}
		v.Unidirectional = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 2 {
		v.Choice = TCMessageChoiceBegin
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding begin: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Begin
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding begin: %w", unmErr)
		}
		v.Begin = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 4 {
		v.Choice = TCMessageChoiceEnd
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding end: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec End
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding end: %w", unmErr)
		}
		v.End = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 5 {
		v.Choice = TCMessageChoiceContinue
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding continue: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Continue
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding continue: %w", unmErr)
		}
		v.Continue = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 7 {
		v.Choice = TCMessageChoiceAbort
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding abort: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Abort
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding abort: %w", unmErr)
		}
		v.Abort = &dec
	} else {
		return fmt.Errorf("unknown tag %s for TCMessage CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Unidirectional to BER format.
func (v *Unidirectional) MarshalBER() ([]byte, error) {
	var children []byte
	if v.DialoguePortion != nil {
		enc_dialogueportion := ber.EncodeOctetString([]byte(*v.DialoguePortion))
		enc_dialogueportion = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 11, false, enc_dialogueportion)
		children = append(children, enc_dialogueportion...)
	}
	enc_components, err := MarshalBERComponentPortion(v.Components)
	if err != nil {
		return nil, fmt.Errorf("encoding components: %w", err)
	}
	if v.ComponentsIndef_ {
		// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
		_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_components)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_components = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassApplication, Number: 12}, seqContent_)
	} else {
		enc_components = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, true, enc_components)
	}
	children = append(children, enc_components...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Unidirectional to DER format.
func (v *Unidirectional) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Unidirectional from BER/DER format.
func (v *Unidirectional) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Unidirectional SEQUENCE: %w", err)
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
				_, n_dialogueportion, rawVal_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
				}
				tmp_dialogueportion := DialoguePortion(rawVal_dialogueportion)
				v.DialoguePortion = &tmp_dialogueportion
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
	_, n_components, rawVal_components, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding components: %w", err)
	}
	reconstructed_components := ber.EncodeSequence(rawVal_components)
	dec_components, unmErr := UnmarshalBERComponentPortion(reconstructed_components)
	if unmErr != nil {
		return fmt.Errorf("decoding components: %w", unmErr)
	}
	v.Components = dec_components
	{
		_, tagSz_, _ := ber.DecodeTag(content[offset:])
		if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
			v.ComponentsIndef_ = true
		}
	}
	offset += n_components
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Unidirectional", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Begin to BER format.
func (v *Begin) MarshalBER() ([]byte, error) {
	var children []byte
	enc_otid := ber.EncodeOctetString([]byte(v.Otid))
	enc_otid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, false, enc_otid)
	children = append(children, enc_otid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion := ber.EncodeOctetString([]byte(*v.DialoguePortion))
		enc_dialogueportion = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 11, false, enc_dialogueportion)
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		enc_components, err := MarshalBERComponentPortion(v.Components)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		if v.ComponentsIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_components = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassApplication, Number: 12}, seqContent_)
		} else {
			enc_components = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, true, enc_components)
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Begin to DER format.
func (v *Begin) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Begin from BER/DER format.
func (v *Begin) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Begin SEQUENCE: %w", err)
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
	_, n_otid, rawVal_otid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding otid: %w", err)
	}
	v.Otid = OrigTransactionID(rawVal_otid)
	offset += n_otid
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				_, n_dialogueportion, rawVal_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
				}
				tmp_dialogueportion := DialoguePortion(rawVal_dialogueportion)
				v.DialoguePortion = &tmp_dialogueportion
				offset += n_dialogueportion
			}
		}
	}
	// Decode components
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				_, n_components, rawVal_components, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding components: %w", err)
				}
				reconstructed_components := ber.EncodeSequence(rawVal_components)
				dec_components, unmErr := UnmarshalBERComponentPortion(reconstructed_components)
				if unmErr != nil {
					return fmt.Errorf("decoding components: %w", unmErr)
				}
				v.Components = dec_components
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				offset += n_components
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Begin", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes End to BER format.
func (v *End) MarshalBER() ([]byte, error) {
	var children []byte
	enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	enc_dtid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, false, enc_dtid)
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion := ber.EncodeOctetString([]byte(*v.DialoguePortion))
		enc_dialogueportion = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 11, false, enc_dialogueportion)
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		enc_components, err := MarshalBERComponentPortion(v.Components)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		if v.ComponentsIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_components = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassApplication, Number: 12}, seqContent_)
		} else {
			enc_components = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, true, enc_components)
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes End to DER format.
func (v *End) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes End from BER/DER format.
func (v *End) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding End SEQUENCE: %w", err)
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
	_, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dtid: %w", err)
	}
	v.Dtid = DestTransactionID(rawVal_dtid)
	offset += n_dtid
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				_, n_dialogueportion, rawVal_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
				}
				tmp_dialogueportion := DialoguePortion(rawVal_dialogueportion)
				v.DialoguePortion = &tmp_dialogueportion
				offset += n_dialogueportion
			}
		}
	}
	// Decode components
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				_, n_components, rawVal_components, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding components: %w", err)
				}
				reconstructed_components := ber.EncodeSequence(rawVal_components)
				dec_components, unmErr := UnmarshalBERComponentPortion(reconstructed_components)
				if unmErr != nil {
					return fmt.Errorf("decoding components: %w", unmErr)
				}
				v.Components = dec_components
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				offset += n_components
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "End", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Continue to BER format.
func (v *Continue) MarshalBER() ([]byte, error) {
	var children []byte
	enc_otid := ber.EncodeOctetString([]byte(v.Otid))
	enc_otid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, false, enc_otid)
	children = append(children, enc_otid...)
	enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	enc_dtid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, false, enc_dtid)
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion := ber.EncodeOctetString([]byte(*v.DialoguePortion))
		enc_dialogueportion = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 11, false, enc_dialogueportion)
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		enc_components, err := MarshalBERComponentPortion(v.Components)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		if v.ComponentsIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_components = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassApplication, Number: 12}, seqContent_)
		} else {
			enc_components = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, true, enc_components)
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Continue to DER format.
func (v *Continue) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Continue from BER/DER format.
func (v *Continue) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Continue SEQUENCE: %w", err)
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
	_, n_otid, rawVal_otid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding otid: %w", err)
	}
	v.Otid = OrigTransactionID(rawVal_otid)
	offset += n_otid
	// Decode dtid
	if offset >= len(content) {
		return fmt.Errorf("missing required field dtid")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 9 {
			return fmt.Errorf("expected tag [%s %d] for dtid, got %s", "APPLICATION", 9, reqTag_)
		}
	}
	_, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dtid: %w", err)
	}
	v.Dtid = DestTransactionID(rawVal_dtid)
	offset += n_dtid
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				_, n_dialogueportion, rawVal_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
				}
				tmp_dialogueportion := DialoguePortion(rawVal_dialogueportion)
				v.DialoguePortion = &tmp_dialogueportion
				offset += n_dialogueportion
			}
		}
	}
	// Decode components
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				_, n_components, rawVal_components, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding components: %w", err)
				}
				reconstructed_components := ber.EncodeSequence(rawVal_components)
				dec_components, unmErr := UnmarshalBERComponentPortion(reconstructed_components)
				if unmErr != nil {
					return fmt.Errorf("decoding components: %w", unmErr)
				}
				v.Components = dec_components
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				offset += n_components
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Continue", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Abort to BER format.
func (v *Abort) MarshalBER() ([]byte, error) {
	var children []byte
	enc_dtid := ber.EncodeOctetString([]byte(v.Dtid))
	enc_dtid = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, false, enc_dtid)
	children = append(children, enc_dtid...)
	if v.Reason != nil {
		enc_reason, err := v.Reason.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reason: %w", err)
		}
		children = append(children, enc_reason...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Abort to DER format.
func (v *Abort) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Abort from BER/DER format.
func (v *Abort) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Abort SEQUENCE: %w", err)
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
	_, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dtid: %w", err)
	}
	v.Dtid = DestTransactionID(rawVal_dtid)
	offset += n_dtid
	// Decode reason
	if offset < len(content) {
		// Decode nested CHOICE (Reason)
		_, n_reason, _, tlvErr_reason := ber.DecodeTLV(content[offset:])
		if tlvErr_reason != nil {
			return fmt.Errorf("decoding reason: %w", tlvErr_reason)
		}
		var dec_reason Reason
		if unmErr := dec_reason.UnmarshalBER(content[offset : offset+n_reason]); unmErr != nil {
			return fmt.Errorf("decoding reason: %w", unmErr)
		}
		v.Reason = &dec_reason
		offset += n_reason
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Abort", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Reason to BER format.
func (v *Reason) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ReasonChoicePAbortCause:
		if v.PAbortCause == nil {
			return nil, fmt.Errorf("choice Reason: p-abortCause is nil")
		}
		enc_0 := ber.EncodeInteger(int64(*v.PAbortCause))
		return enc_0, nil
	case ReasonChoiceUAbortCause:
		enc_1 := ber.EncodeOctetString([]byte(*v.UAbortCause))
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Reason", v.Choice)
	}
}

// MarshalDER encodes Reason to DER format.
func (v *Reason) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes Reason from BER/DER format.
func (v *Reason) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Reason CHOICE")
	}
	peekTag, peekErr := ber.PeekTag(data)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Reason: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(data)
	if tlvErr != nil {
		return fmt.Errorf("decoding Reason CHOICE: %w", tlvErr)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Reason", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 10 {
		v.Choice = ReasonChoicePAbortCause
		decVal, _, intErr := ber.DecodeInteger(data)
		if intErr != nil {
			return fmt.Errorf("decoding p-abortCause: %w", intErr)
		}
		v.PAbortCause = &decVal
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
		v.Choice = ReasonChoiceUAbortCause
		decVal, _, osErr := ber.DecodeOctetString(data)
		if osErr != nil {
			return fmt.Errorf("decoding u-abortCause: %w", osErr)
		}
		tmp := DialoguePortion(decVal)
		v.UAbortCause = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for Reason CHOICE", peekTag)
	}
	return nil
}

// MarshalBERComponentPortion encodes a ComponentPortion list to BER.
func MarshalBERComponentPortion(list ComponentPortion) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERComponentPortion decodes a ComponentPortion list from BER.
func UnmarshalBERComponentPortion(data []byte) (ComponentPortion, error) {
	_, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ComponentPortion: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ComponentPortion", Cause: ber.ErrExtraData}
	}
	var result ComponentPortion
	offset := 0
	for offset < len(content) {
		var elem Component
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes Component to BER format.
func (v *Component) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ComponentChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice Component: invoke is nil")
		}
		enc_0, err := v.Invoke.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_0)
		return enc_0, nil
	case ComponentChoiceReturnResultLast:
		if v.ReturnResultLast == nil {
			return nil, fmt.Errorf("choice Component: returnResultLast is nil")
		}
		enc_1, err := v.ReturnResultLast.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultLast: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_1)
		return enc_1, nil
	case ComponentChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice Component: returnError is nil")
		}
		enc_2, err := v.ReturnError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	case ComponentChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice Component: reject is nil")
		}
		enc_3, err := v.Reject.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_3)
		return enc_3, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("choice Component: returnResultNotLast is nil")
		}
		enc_4, err := v.ReturnResultNotLast.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", err)
		}
		enc_4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_4)
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Component", v.Choice)
	}
}

// MarshalDER encodes Component to DER format.
func (v *Component) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes Component from BER/DER format.
func (v *Component) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Component CHOICE")
	}
	peekTag, peekErr := ber.PeekTag(data)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Component: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(data)
	if tlvErr != nil {
		return fmt.Errorf("decoding Component CHOICE: %w", tlvErr)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Component", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = ComponentChoiceInvoke
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding invoke: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Invoke
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding invoke: %w", unmErr)
		}
		v.Invoke = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ComponentChoiceReturnResultLast
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResultLast: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnResultLast: %w", unmErr)
		}
		v.ReturnResultLast = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = ComponentChoiceReturnError
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnError: %w", unmErr)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = ComponentChoiceReject
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding reject: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding reject: %w", unmErr)
		}
		v.Reject = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
		v.Choice = ComponentChoiceReturnResultNotLast
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResultNotLast: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnResultNotLast: %w", unmErr)
		}
		v.ReturnResultNotLast = &dec
	} else {
		return fmt.Errorf("unknown tag %s for Component CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Invoke to BER format.
func (v *Invoke) MarshalBER() ([]byte, error) {
	var children []byte
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	if v.LinkedID != nil {
		enc_linkedid := ber.EncodeInteger(int64(*v.LinkedID))
		enc_linkedid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_linkedid)
		children = append(children, enc_linkedid...)
	}
	enc_opcode, err := v.OpCode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding opCode: %w", err)
	}
	children = append(children, enc_opcode...)
	if v.Parameter != nil {
		enc_parameter := v.Parameter.Bytes
		children = append(children, enc_parameter...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Invoke to DER format.
func (v *Invoke) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Invoke from BER/DER format.
func (v *Invoke) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Invoke SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Invoke", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeID
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeID")
	}
	val_invokeid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding invokeID: %w", err)
	}
	v.InvokeID = val_invokeid
	offset += n
	// Decode linkedID
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_linkedid, rawVal_linkedid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding linkedID: %w", err)
				}
				decVal_linkedid, intErr := ber.DecodeIntegerValue(rawVal_linkedid)
				if intErr != nil {
					return fmt.Errorf("decoding linkedID: %w", intErr)
				}
				v.LinkedID = &decVal_linkedid
				offset += n_linkedid
			}
		}
	}
	// Decode opCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opCode")
	}
	// Decode nested CHOICE (OPERATION)
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:])
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opCode: %w", tlvErr_opcode)
	}
	if unmErr := v.OpCode.UnmarshalBER(content[offset : offset+n_opcode]); unmErr != nil {
		return fmt.Errorf("decoding opCode: %w", unmErr)
	}
	offset += n_opcode
	// Decode parameter
	if offset < len(content) {
		_, n_parameter, _, tlvErr_parameter := ber.DecodeTLV(content[offset:])
		if tlvErr_parameter != nil {
			return fmt.Errorf("decoding parameter: %w", tlvErr_parameter)
		}
		tmp_parameter := runtime.RawValue{Bytes: content[offset : offset+n_parameter]}
		v.Parameter = &tmp_parameter
		offset += n_parameter
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Invoke", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ReturnResult to BER format.
func (v *ReturnResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	if v.Resultretres != nil {
		enc_resultretres, err := v.Resultretres.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding resultretres: %w", err)
		}
		children = append(children, enc_resultretres...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ReturnResult to DER format.
func (v *ReturnResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ReturnResult from BER/DER format.
func (v *ReturnResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReturnResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeID
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeID")
	}
	val_invokeid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding invokeID: %w", err)
	}
	v.InvokeID = val_invokeid
	offset += n
	// Decode resultretres
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ReturnResultResultretres)
				_, n_resultretres, _, tlvErr_resultretres := ber.DecodeTLV(content[offset:])
				if tlvErr_resultretres != nil {
					return fmt.Errorf("decoding resultretres: %w", tlvErr_resultretres)
				}
				var dec_resultretres ReturnResultResultretres
				if unmErr := dec_resultretres.UnmarshalBER(content[offset : offset+n_resultretres]); unmErr != nil {
					return fmt.Errorf("decoding resultretres: %w", unmErr)
				}
				v.Resultretres = &dec_resultretres
				offset += n_resultretres
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ReturnError to BER format.
func (v *ReturnError) MarshalBER() ([]byte, error) {
	var children []byte
	enc_invokeid := ber.EncodeInteger(int64(v.InvokeID))
	children = append(children, enc_invokeid...)
	enc_errorcode, err := v.ErrorCode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding errorCode: %w", err)
	}
	children = append(children, enc_errorcode...)
	if v.Parameter != nil {
		enc_parameter := v.Parameter.Bytes
		children = append(children, enc_parameter...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ReturnError to DER format.
func (v *ReturnError) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ReturnError from BER/DER format.
func (v *ReturnError) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReturnError SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnError", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeID
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeID")
	}
	val_invokeid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding invokeID: %w", err)
	}
	v.InvokeID = val_invokeid
	offset += n
	// Decode errorCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field errorCode")
	}
	// Decode nested CHOICE (ErrorCode)
	_, n_errorcode, _, tlvErr_errorcode := ber.DecodeTLV(content[offset:])
	if tlvErr_errorcode != nil {
		return fmt.Errorf("decoding errorCode: %w", tlvErr_errorcode)
	}
	if unmErr := v.ErrorCode.UnmarshalBER(content[offset : offset+n_errorcode]); unmErr != nil {
		return fmt.Errorf("decoding errorCode: %w", unmErr)
	}
	offset += n_errorcode
	// Decode parameter
	if offset < len(content) {
		_, n_parameter, _, tlvErr_parameter := ber.DecodeTLV(content[offset:])
		if tlvErr_parameter != nil {
			return fmt.Errorf("decoding parameter: %w", tlvErr_parameter)
		}
		tmp_parameter := runtime.RawValue{Bytes: content[offset : offset+n_parameter]}
		v.Parameter = &tmp_parameter
		offset += n_parameter
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnError", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Reject to BER format.
func (v *Reject) MarshalBER() ([]byte, error) {
	var children []byte
	enc_invokeidrej, err := v.InvokeIDRej.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding invokeIDRej: %w", err)
	}
	children = append(children, enc_invokeidrej...)
	enc_problem, err := v.Problem.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding problem: %w", err)
	}
	children = append(children, enc_problem...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Reject to DER format.
func (v *Reject) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes Reject from BER/DER format.
func (v *Reject) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding Reject SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "Reject", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode invokeIDRej
	if offset >= len(content) {
		return fmt.Errorf("missing required field invokeIDRej")
	}
	// Decode nested CHOICE (RejectInvokeIDRej)
	_, n_invokeidrej, _, tlvErr_invokeidrej := ber.DecodeTLV(content[offset:])
	if tlvErr_invokeidrej != nil {
		return fmt.Errorf("decoding invokeIDRej: %w", tlvErr_invokeidrej)
	}
	if unmErr := v.InvokeIDRej.UnmarshalBER(content[offset : offset+n_invokeidrej]); unmErr != nil {
		return fmt.Errorf("decoding invokeIDRej: %w", unmErr)
	}
	offset += n_invokeidrej
	// Decode problem
	if offset >= len(content) {
		return fmt.Errorf("missing required field problem")
	}
	// Decode nested CHOICE (RejectProblem)
	_, n_problem, _, tlvErr_problem := ber.DecodeTLV(content[offset:])
	if tlvErr_problem != nil {
		return fmt.Errorf("decoding problem: %w", tlvErr_problem)
	}
	if unmErr := v.Problem.UnmarshalBER(content[offset : offset+n_problem]); unmErr != nil {
		return fmt.Errorf("decoding problem: %w", unmErr)
	}
	offset += n_problem
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Reject", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes OPERATION to BER format.
func (v *OPERATION) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case OPERATIONChoiceLocalValue:
		if v.LocalValue == nil {
			return nil, fmt.Errorf("choice OPERATION: localValue is nil")
		}
		enc_0 := ber.EncodeBigInt(v.LocalValue)
		return enc_0, nil
	case OPERATIONChoiceGlobalValue:
		enc_1 := ber.EncodeObjectIdentifier([]uint64(v.GlobalValue))
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for OPERATION", v.Choice)
	}
}

// MarshalDER encodes OPERATION to DER format.
func (v *OPERATION) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes OPERATION from BER/DER format.
func (v *OPERATION) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for OPERATION CHOICE")
	}
	peekTag, peekErr := ber.PeekTag(data)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for OPERATION: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(data)
	if tlvErr != nil {
		return fmt.Errorf("decoding OPERATION CHOICE: %w", tlvErr)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OPERATION", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = OPERATIONChoiceLocalValue
		decVal, _, intErr := ber.DecodeBigInt(data)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		v.LocalValue = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 {
		v.Choice = OPERATIONChoiceGlobalValue
		decVal, _, oidErr := ber.DecodeObjectIdentifier(data)
		if oidErr != nil {
			return fmt.Errorf("decoding globalValue: %w", oidErr)
		}
		tmp := runtime.ObjectIdentifier(decVal)
		v.GlobalValue = tmp
	} else {
		return fmt.Errorf("unknown tag %s for OPERATION CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ERROR to BER format.
func (v *ERROR) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ERRORChoiceLocalValue:
		if v.LocalValue == nil {
			return nil, fmt.Errorf("choice ERROR: localValue is nil")
		}
		enc_0 := ber.EncodeBigInt(v.LocalValue)
		return enc_0, nil
	case ERRORChoiceGlobalValue:
		enc_1 := ber.EncodeObjectIdentifier([]uint64(v.GlobalValue))
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ERROR", v.Choice)
	}
}

// MarshalDER encodes ERROR to DER format.
func (v *ERROR) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes ERROR from BER/DER format.
func (v *ERROR) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ERROR CHOICE")
	}
	peekTag, peekErr := ber.PeekTag(data)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ERROR: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(data)
	if tlvErr != nil {
		return fmt.Errorf("decoding ERROR CHOICE: %w", tlvErr)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ERROR", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = ERRORChoiceLocalValue
		decVal, _, intErr := ber.DecodeBigInt(data)
		if intErr != nil {
			return fmt.Errorf("decoding localValue: %w", intErr)
		}
		v.LocalValue = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 {
		v.Choice = ERRORChoiceGlobalValue
		decVal, _, oidErr := ber.DecodeObjectIdentifier(data)
		if oidErr != nil {
			return fmt.Errorf("decoding globalValue: %w", oidErr)
		}
		tmp := runtime.ObjectIdentifier(decVal)
		v.GlobalValue = tmp
	} else {
		return fmt.Errorf("unknown tag %s for ERROR CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ErrorCode to BER format.
func (v *ErrorCode) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ErrorCodeChoiceNationaler:
		if v.Nationaler == nil {
			return nil, fmt.Errorf("choice ErrorCode: nationaler is nil")
		}
		enc_0 := ber.EncodeInteger(int64(*v.Nationaler))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 19, false, enc_0)
		return enc_0, nil
	case ErrorCodeChoicePrivateer:
		if v.Privateer == nil {
			return nil, fmt.Errorf("choice ErrorCode: privateer is nil")
		}
		enc_1 := ber.EncodeBigInt(v.Privateer)
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 20, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ErrorCode", v.Choice)
	}
}

// MarshalDER encodes ErrorCode to DER format.
func (v *ErrorCode) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes ErrorCode from BER/DER format.
func (v *ErrorCode) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ErrorCode CHOICE")
	}
	peekTag, peekErr := ber.PeekTag(data)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ErrorCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(data)
	if tlvErr != nil {
		return fmt.Errorf("decoding ErrorCode CHOICE: %w", tlvErr)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ErrorCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassPrivate && peekTag.Number == 19 {
		v.Choice = ErrorCodeChoiceNationaler
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding nationaler: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding nationaler: %w", intErr)
		}
		v.Nationaler = &decVal
	} else if peekTag.Class == tag.ClassPrivate && peekTag.Number == 20 {
		v.Choice = ErrorCodeChoicePrivateer
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding privateer: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding privateer: %w", intErr)
		}
		v.Privateer = decVal
	} else {
		return fmt.Errorf("unknown tag %s for ErrorCode CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ReturnResultResultretres to BER format.
func (v *ReturnResultResultretres) MarshalBER() ([]byte, error) {
	var children []byte
	enc_opcode, err := v.OpCode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding opCode: %w", err)
	}
	children = append(children, enc_opcode...)
	if v.Parameter != nil {
		enc_parameter := v.Parameter.Bytes
		children = append(children, enc_parameter...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ReturnResultResultretres to DER format.
func (v *ReturnResultResultretres) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ReturnResultResultretres from BER/DER format.
func (v *ReturnResultResultretres) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ReturnResultResultretres SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReturnResultResultretres", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opCode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opCode")
	}
	// Decode nested CHOICE (OPERATION)
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:])
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opCode: %w", tlvErr_opcode)
	}
	if unmErr := v.OpCode.UnmarshalBER(content[offset : offset+n_opcode]); unmErr != nil {
		return fmt.Errorf("decoding opCode: %w", unmErr)
	}
	offset += n_opcode
	// Decode parameter
	if offset < len(content) {
		_, n_parameter, _, tlvErr_parameter := ber.DecodeTLV(content[offset:])
		if tlvErr_parameter != nil {
			return fmt.Errorf("decoding parameter: %w", tlvErr_parameter)
		}
		tmp_parameter := runtime.RawValue{Bytes: content[offset : offset+n_parameter]}
		v.Parameter = &tmp_parameter
		offset += n_parameter
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ReturnResultResultretres", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RejectInvokeIDRej to BER format.
func (v *RejectInvokeIDRej) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case RejectInvokeIDRejChoiceDerivable:
		if v.Derivable == nil {
			return nil, fmt.Errorf("choice RejectInvokeIDRej: derivable is nil")
		}
		enc_0 := ber.EncodeInteger(int64(*v.Derivable))
		return enc_0, nil
	case RejectInvokeIDRejChoiceNotDerivable:
		enc_1 := ber.EncodeNull()
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RejectInvokeIDRej", v.Choice)
	}
}

// MarshalDER encodes RejectInvokeIDRej to DER format.
func (v *RejectInvokeIDRej) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes RejectInvokeIDRej from BER/DER format.
func (v *RejectInvokeIDRej) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for RejectInvokeIDRej CHOICE")
	}
	peekTag, peekErr := ber.PeekTag(data)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RejectInvokeIDRej: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(data)
	if tlvErr != nil {
		return fmt.Errorf("decoding RejectInvokeIDRej CHOICE: %w", tlvErr)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RejectInvokeIDRej", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = RejectInvokeIDRejChoiceDerivable
		decVal, _, intErr := ber.DecodeInteger(data)
		if intErr != nil {
			return fmt.Errorf("decoding derivable: %w", intErr)
		}
		v.Derivable = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
		v.Choice = RejectInvokeIDRejChoiceNotDerivable
		_, nullErr := ber.DecodeNull(data)
		if nullErr != nil {
			return fmt.Errorf("decoding not-derivable: %w", nullErr)
		}
	} else {
		return fmt.Errorf("unknown tag %s for RejectInvokeIDRej CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes RejectProblem to BER format.
func (v *RejectProblem) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case RejectProblemChoiceGeneralProblem:
		if v.GeneralProblem == nil {
			return nil, fmt.Errorf("choice RejectProblem: generalProblem is nil")
		}
		enc_0 := ber.EncodeInteger(int64(*v.GeneralProblem))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case RejectProblemChoiceInvokeProblem:
		if v.InvokeProblem == nil {
			return nil, fmt.Errorf("choice RejectProblem: invokeProblem is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.InvokeProblem))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	case RejectProblemChoiceReturnResultProblem:
		if v.ReturnResultProblem == nil {
			return nil, fmt.Errorf("choice RejectProblem: returnResultProblem is nil")
		}
		enc_2 := ber.EncodeInteger(int64(*v.ReturnResultProblem))
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_2)
		return enc_2, nil
	case RejectProblemChoiceReturnErrorProblem:
		if v.ReturnErrorProblem == nil {
			return nil, fmt.Errorf("choice RejectProblem: returnErrorProblem is nil")
		}
		enc_3 := ber.EncodeInteger(int64(*v.ReturnErrorProblem))
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RejectProblem", v.Choice)
	}
}

// MarshalDER encodes RejectProblem to DER format.
func (v *RejectProblem) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes RejectProblem from BER/DER format.
func (v *RejectProblem) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for RejectProblem CHOICE")
	}
	peekTag, peekErr := ber.PeekTag(data)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RejectProblem: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(data)
	if tlvErr != nil {
		return fmt.Errorf("decoding RejectProblem CHOICE: %w", tlvErr)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RejectProblem", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = RejectProblemChoiceGeneralProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding generalProblem: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding generalProblem: %w", intErr)
		}
		v.GeneralProblem = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = RejectProblemChoiceInvokeProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding invokeProblem: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding invokeProblem: %w", intErr)
		}
		v.InvokeProblem = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = RejectProblemChoiceReturnResultProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResultProblem: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding returnResultProblem: %w", intErr)
		}
		v.ReturnResultProblem = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = RejectProblemChoiceReturnErrorProblem
		_, _, rawVal, tlvErr := ber.DecodeTLV(data)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnErrorProblem: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding returnErrorProblem: %w", intErr)
		}
		v.ReturnErrorProblem = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for RejectProblem CHOICE", peekTag)
	}
	return nil
}
