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
	berOriginal_   []byte          `json:"-"`
	berSnapshot_   []byte          `json:"-"`
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
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *ComponentPortion `asn1:"tag:12,application,implicit"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
	berOriginal_     []byte            `asn1:"-" json:"-"`
	berSnapshot_     []byte            `asn1:"-" json:"-"`
}

// Begin represents the ASN.1 type Begin (SEQUENCE).
type Begin struct {
	Otid             OrigTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *ComponentPortion `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
	berOriginal_     []byte            `asn1:"-" json:"-"`
	berSnapshot_     []byte            `asn1:"-" json:"-"`
}

// End represents the ASN.1 type End (SEQUENCE).
type End struct {
	Dtid             DestTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *ComponentPortion `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
	berOriginal_     []byte            `asn1:"-" json:"-"`
	berSnapshot_     []byte            `asn1:"-" json:"-"`
}

// Continue represents the ASN.1 type Continue (SEQUENCE).
type Continue struct {
	Otid             OrigTransactionID `asn1:""`
	Dtid             DestTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       *ComponentPortion `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
	berOriginal_     []byte            `asn1:"-" json:"-"`
	berSnapshot_     []byte            `asn1:"-" json:"-"`
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
	Values       []Component `json:"Values"`
	berOriginal_ []byte      `json:"-"`
	berSnapshot_ []byte      `json:"-"`
}

// Component choice constants.
const (
	ComponentChoiceBasicROS            = 1
	ComponentChoiceReturnResultNotLast = 2
)

// Component represents the ASN.1 CHOICE type Component.
type Component struct {
	Choice              int
	berOriginal_        []byte        `json:"-"`
	berSnapshot_        []byte        `json:"-"`
	BasicROS            *ROS          `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult `json:"ReturnResultNotLast,omitempty"`
}

// NewComponentBasicROS creates a Component with the basicROS alternative.
func NewComponentBasicROS(v ROS) Component {
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

// ComponentBasicROSInvokeLinkedId choice constants.
const (
	ComponentBasicROSInvokeLinkedIdChoicePresent = 1
	ComponentBasicROSInvokeLinkedIdChoiceAbsent  = 2
)

// ComponentBasicROSInvokeLinkedId represents the ASN.1 CHOICE type Component-basicROS-invoke-linkedId.
type ComponentBasicROSInvokeLinkedId struct {
	Choice       int
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
	Present      *big.Int  `json:"Present,omitempty"`
	Absent       *struct{} `json:"Absent,omitempty"`
}

// NewComponentBasicROSInvokeLinkedIdPresent creates a ComponentBasicROSInvokeLinkedId with the present alternative.
func NewComponentBasicROSInvokeLinkedIdPresent(v *big.Int) ComponentBasicROSInvokeLinkedId {
	return ComponentBasicROSInvokeLinkedId{
		Choice:  ComponentBasicROSInvokeLinkedIdChoicePresent,
		Present: v,
	}
}

// NewComponentBasicROSInvokeLinkedIdAbsent creates a ComponentBasicROSInvokeLinkedId with the absent alternative.
func NewComponentBasicROSInvokeLinkedIdAbsent(v struct{}) ComponentBasicROSInvokeLinkedId {
	return ComponentBasicROSInvokeLinkedId{
		Choice: ComponentBasicROSInvokeLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// ComponentBasicROSReturnResultResult represents the ASN.1 type Component-basicROS-returnResult-result (SEQUENCE).
type ComponentBasicROSReturnResultResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// ComponentReturnResultNotLastResult represents the ASN.1 type Component-returnResultNotLast-result (SEQUENCE).
type ComponentReturnResultNotLastResult struct {
	Opcode       Code             `asn1:""`
	Result       runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berOriginal_ []byte           `asn1:"-" json:"-"`
	berSnapshot_ []byte           `asn1:"-" json:"-"`
}

// MarshalBER encodes TCMessage to BER format.
func (v *TCMessage) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_0, err := v.Unidirectional.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding unidirectional: %w", err)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding unidirectional: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case TCMessageChoiceBegin:
		if v.Begin == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: begin is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.Begin.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding begin: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding begin: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case TCMessageChoiceEnd:
		if v.End == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: end is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.End.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding end: %w", err)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 4, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding end: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case TCMessageChoiceContinue:
		if v.Continue == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: continue is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.Continue.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding continue: %w", err)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 5, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding continue: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	case TCMessageChoiceAbort:
		if v.Abort == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: abort is nil", ber.ErrInvalidValue)
		}
		enc_4, err := v.Abort.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding abort: %w", err)
		}
		retagged_enc_4, tagErr_enc_4 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 7, enc_4)
		if tagErr_enc_4 != nil {
			return nil, fmt.Errorf("encoding abort: %w", tagErr_enc_4)
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
			return nil, fmt.Errorf("encoding unidirectional: %w", err)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding unidirectional: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding unidirectional as DER: %w", derErr)
		}
		return enc_der_0, nil
	case TCMessageChoiceBegin:
		if v.Begin == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: begin is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.Begin.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding begin: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding begin: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding begin as DER: %w", derErr)
		}
		return enc_der_1, nil
	case TCMessageChoiceEnd:
		if v.End == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: end is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.End.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding end: %w", err)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 4, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, fmt.Errorf("encoding end: %w", tagErr_enc_der_2)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding end as DER: %w", derErr)
		}
		return enc_der_2, nil
	case TCMessageChoiceContinue:
		if v.Continue == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: continue is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.Continue.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding continue: %w", err)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 5, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, fmt.Errorf("encoding continue: %w", tagErr_enc_der_3)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, fmt.Errorf("encoding continue as DER: %w", derErr)
		}
		return enc_der_3, nil
	case TCMessageChoiceAbort:
		if v.Abort == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: abort is nil", ber.ErrInvalidValue)
		}
		enc_der_4, err := v.Abort.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding abort: %w", err)
		}
		retagged_enc_der_4, tagErr_enc_der_4 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 7, enc_der_4)
		if tagErr_enc_der_4 != nil {
			return nil, fmt.Errorf("encoding abort: %w", tagErr_enc_der_4)
		}
		enc_der_4 = retagged_enc_der_4
		if derErr := ber.ValidateDEREncodedElement(enc_der_4); derErr != nil {
			return nil, fmt.Errorf("encoding abort as DER: %w", derErr)
		}
		return enc_der_4, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TCMessage as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessage from BER/DER format.
func (v *TCMessage) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCMessage destination is nil", ber.ErrInvalidValue)
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
		return fmt.Errorf("decoding TCMessage CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessage", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceUnidirectional
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding unidirectional: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Unidirectional
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding unidirectional: %w", unmErr)
		}
		v.Unidirectional = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceBegin
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding begin: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Begin
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding begin: %w", unmErr)
		}
		v.Begin = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceEnd
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding end: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec End
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding end: %w", unmErr)
		}
		v.End = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 5 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceContinue
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding continue: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Continue
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding continue: %w", unmErr)
		}
		v.Continue = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceAbort
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding abort: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Abort
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding abort: %w", unmErr)
		}
		v.Abort = &dec
	} else {
		return fmt.Errorf("unknown tag %s for TCMessage CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes Unidirectional to BER format.
func (v *Unidirectional) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(opts...)
		if extErr != nil {
			return nil, fmt.Errorf("encoding dialoguePortion: %w", extErr)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components == nil {
		return nil, fmt.Errorf("encoding components: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.Components).Values) < 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_components, err := MarshalBERComponentPortion(v.Components, opts...)
	if err != nil {
		return nil, fmt.Errorf("encoding components: %w", err)
	}
	if v.ComponentsIndef_ {
		indefTag_, _, indefContent_, tlvErr_ := ber.DecodeTLV(enc_components)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		{
			var encodeErr error
			enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding Components: %w", encodeErr)
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
			return nil, fmt.Errorf("encoding dialoguePortion: %w", extErr)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components == nil {
		return nil, fmt.Errorf("encoding components: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.Components).Values) < 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_components, err := MarshalDERComponentPortion(v.Components)
	if err != nil {
		return nil, fmt.Errorf("encoding components: %w", err)
	}
	children = append(children, enc_components...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Unidirectional as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Unidirectional from BER/DER format.
func (v *Unidirectional) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Unidirectional destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = Unidirectional{}
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
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", extErr)
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
	if offset >= len(content) {
		return fmt.Errorf("missing required field components")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassApplication || reqTag_.Number != 12 {
			return fmt.Errorf("expected tag [%s %d] for components, got %s", "APPLICATION", 12, reqTag_)
		}
	}
	v.ComponentsIndef_ = false
	// Decode nested SEQUENCE_OF (ComponentPortion)
	_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_components != nil {
		return fmt.Errorf("decoding components: %w", tlvErr_components)
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
	dec_components, unmErr := UnmarshalBERComponentPortion(tlv_components, ber.ChildDecodeOptions(opts, "components")...)
	if unmErr != nil {
		return fmt.Errorf("decoding components: %w", unmErr)
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
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Unidirectional", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes Begin to BER format.
func (v *Begin) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		return nil, fmt.Errorf("encoding otid: %w", encodeErr_enc_otid)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, fmt.Errorf("encoding otid: %w", tagErr_enc_otid)
	}
	enc_otid = retagged_enc_otid
	children = append(children, enc_otid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(opts...)
		if extErr != nil {
			return nil, fmt.Errorf("encoding dialoguePortion: %w", extErr)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalBERComponentPortion(v.Components, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		if v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding Components: %w", encodeErr)
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
		return nil, fmt.Errorf("encoding otid: %w", encodeErr_enc_otid)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, fmt.Errorf("encoding otid: %w", tagErr_enc_otid)
	}
	enc_otid = retagged_enc_otid
	children = append(children, enc_otid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, fmt.Errorf("encoding dialoguePortion: %w", extErr)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalDERComponentPortion(v.Components)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		children = append(children, enc_components...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Begin as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Begin from BER/DER format.
func (v *Begin) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Begin destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = Begin{}
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
	decodedTag_otid, n_otid, rawVal_otid, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding otid: %w", err)
	}
	if decodedTag_otid.Class != tag.ClassApplication || decodedTag_otid.Number != 8 {
		return fmt.Errorf("decoding otid: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_otid)
	}
	v.Otid = OrigTransactionID(rawVal_otid)
	if offset < 0 || offset >
		len(content) || n_otid < 0 || n_otid > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_otid
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckDecodedLength(opts, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", extErr)
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
				// Decode nested SEQUENCE_OF (ComponentPortion)
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_components != nil {
					return fmt.Errorf("decoding components: %w", tlvErr_components)
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
				dec_components, unmErr := UnmarshalBERComponentPortion(tlv_components, ber.ChildDecodeOptions(opts, "components")...)
				if unmErr != nil {
					return fmt.Errorf("decoding components: %w", unmErr)
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
func (v *End) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		return nil, fmt.Errorf("encoding dtid: %w", encodeErr_enc_dtid)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, fmt.Errorf("encoding dtid: %w", tagErr_enc_dtid)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(opts...)
		if extErr != nil {
			return nil, fmt.Errorf("encoding dialoguePortion: %w", extErr)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalBERComponentPortion(v.Components, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		if v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding Components: %w", encodeErr)
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
		return nil, fmt.Errorf("encoding dtid: %w", encodeErr_enc_dtid)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, fmt.Errorf("encoding dtid: %w", tagErr_enc_dtid)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, fmt.Errorf("encoding dialoguePortion: %w", extErr)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalDERComponentPortion(v.Components)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		children = append(children, enc_components...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding End as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes End from BER/DER format.
func (v *End) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: End destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = End{}
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
	decodedTag_dtid, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding dtid: %w", err)
	}
	if decodedTag_dtid.Class != tag.ClassApplication || decodedTag_dtid.Number != 9 {
		return fmt.Errorf("decoding dtid: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dtid)
	}
	v.Dtid = DestTransactionID(rawVal_dtid)
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
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", extErr)
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
				// Decode nested SEQUENCE_OF (ComponentPortion)
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_components != nil {
					return fmt.Errorf("decoding components: %w", tlvErr_components)
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
				dec_components, unmErr := UnmarshalBERComponentPortion(tlv_components, ber.ChildDecodeOptions(opts, "components")...)
				if unmErr != nil {
					return fmt.Errorf("decoding components: %w", unmErr)
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
func (v *Continue) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		return nil, fmt.Errorf("encoding otid: %w", encodeErr_enc_otid)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, fmt.Errorf("encoding otid: %w", tagErr_enc_otid)
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
		return nil, fmt.Errorf("encoding dtid: %w", encodeErr_enc_dtid)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, fmt.Errorf("encoding dtid: %w", tagErr_enc_dtid)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(opts...)
		if extErr != nil {
			return nil, fmt.Errorf("encoding dialoguePortion: %w", extErr)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalBERComponentPortion(v.Components, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		if v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding Components: %w", encodeErr)
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
		return nil, fmt.Errorf("encoding otid: %w", encodeErr_enc_otid)
	}
	retagged_enc_otid, tagErr_enc_otid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 8, enc_otid)
	if tagErr_enc_otid != nil {
		return nil, fmt.Errorf("encoding otid: %w", tagErr_enc_otid)
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
		return nil, fmt.Errorf("encoding dtid: %w", encodeErr_enc_dtid)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, fmt.Errorf("encoding dtid: %w", tagErr_enc_dtid)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, fmt.Errorf("encoding dialoguePortion: %w", extErr)
		}
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := MarshalDERComponentPortion(v.Components)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		children = append(children, enc_components...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Continue as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Continue from BER/DER format.
func (v *Continue) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Continue destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = Continue{}
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
	decodedTag_otid, n_otid, rawVal_otid, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding otid: %w", err)
	}
	if decodedTag_otid.Class != tag.ClassApplication || decodedTag_otid.Number != 8 {
		return fmt.Errorf("decoding otid: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_otid)
	}
	v.Otid = OrigTransactionID(rawVal_otid)
	if offset < 0 || offset >
		len(content) || n_otid < 0 || n_otid > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_otid
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckDecodedLength(opts, "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
			return constraintErr
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
	decodedTag_dtid, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding dtid: %w", err)
	}
	if decodedTag_dtid.Class != tag.ClassApplication || decodedTag_dtid.Number != 9 {
		return fmt.Errorf("decoding dtid: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dtid)
	}
	v.Dtid = DestTransactionID(rawVal_dtid)
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
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				_, n_dialogueportion, _, extErr := ber.DecodeTLV(content[offset:], opts...)
				if extErr != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", extErr)
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
				// Decode nested SEQUENCE_OF (ComponentPortion)
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_components != nil {
					return fmt.Errorf("decoding components: %w", tlvErr_components)
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
				dec_components, unmErr := UnmarshalBERComponentPortion(tlv_components, ber.ChildDecodeOptions(opts, "components")...)
				if unmErr != nil {
					return fmt.Errorf("decoding components: %w", unmErr)
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
func (v *Abort) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		return nil, fmt.Errorf("encoding dtid: %w", encodeErr_enc_dtid)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, fmt.Errorf("encoding dtid: %w", tagErr_enc_dtid)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.Reason != nil {
		enc_reason, err := v.Reason.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding reason: %w", err)
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
		return nil, fmt.Errorf("encoding dtid: %w", encodeErr_enc_dtid)
	}
	retagged_enc_dtid, tagErr_enc_dtid := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 9, enc_dtid)
	if tagErr_enc_dtid != nil {
		return nil, fmt.Errorf("encoding dtid: %w", tagErr_enc_dtid)
	}
	enc_dtid = retagged_enc_dtid
	children = append(children, enc_dtid...)
	if v.Reason != nil {
		enc_reason, err := v.Reason.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reason: %w", err)
		}
		children = append(children, enc_reason...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Abort as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Abort from BER/DER format.
func (v *Abort) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Abort destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = Abort{}
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
	decodedTag_dtid, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding dtid: %w", err)
	}
	if decodedTag_dtid.Class != tag.ClassApplication || decodedTag_dtid.Number != 9 {
		return fmt.Errorf("decoding dtid: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dtid)
	}
	v.Dtid = DestTransactionID(rawVal_dtid)
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
	// Decode reason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassApplication && peekTag.Number == 10) || (peekTag.Class == tag.ClassApplication && peekTag.Number == 11) {
				// Decode nested CHOICE (AbortReason)
				_, n_reason, _, tlvErr_reason := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_reason != nil {
					return fmt.Errorf("decoding reason: %w", tlvErr_reason)
				}
				var dec_reason AbortReason
				if offset < 0 || offset >
					len(content) || n_reason < 0 || n_reason > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_reason.UnmarshalBER(content[offset:offset+n_reason], ber.ChildDecodeOptions(opts, "reason")...); unmErr != nil {
					return fmt.Errorf("decoding reason: %w", unmErr)
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
	if original := runtime.External(*v).UnchangedBER(); original != nil {
		return original, nil
	}
	encoded, err := ber.EncodeExternal(runtime.External(*v))
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
		return err
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
func MarshalBERComponentPortion(collection *ComponentPortion, opts ...ber.EncodeOption) ([]byte, error) {
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
		if constraintErr := ber.CheckEncodedLength(opts, "ComponentPortion", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
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
		if constraintErr := ber.CheckEncodedLength(nil, "ComponentPortion", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 12, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding ComponentPortion: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ComponentPortion as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERComponentPortion decodes a ComponentPortion list from BER.
func UnmarshalBERComponentPortion(data []byte, opts ...ber.DecodeOption) (*ComponentPortion, error) {
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding ComponentPortion: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding ComponentPortion: %w: expected tag [APPLICATION 12], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ComponentPortion", Cause: ber.ErrExtraData}
	}
	var result []Component
	offset := 0
	for offset < len(content) {
		var elem Component
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		if unmErr := elem.UnmarshalBER(content[offset:offset+n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ComponentPortion", "SIZE (1..MAX)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &ComponentPortion{Values: result}
	if ber.ConstraintToleranceEnabled(opts) {
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
func (v *Component) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		enc_0, err := v.BasicROS.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicROS: %w", err)
		}
		return enc_0, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice Component: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", tagErr_enc_1)
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
			return nil, fmt.Errorf("encoding basicROS: %w", err)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding basicROS as DER: %w", derErr)
		}
		return enc_der_0, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice Component: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Component as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Component from BER/DER format.
func (v *Component) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Component destination is nil", ber.ErrInvalidValue)
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
		return fmt.Errorf("decoding Component CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Component", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = ComponentChoiceReturnResultNotLast
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResultNotLast: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding returnResultNotLast: %w", unmErr)
		}
		v.ReturnResultNotLast = &dec
	} else {
		v.Choice = ComponentChoiceBasicROS
		var dec ROS
		if unmErr := dec.UnmarshalBER(choiceData, opts...); unmErr != nil {
			return fmt.Errorf("decoding basicROS: %w", unmErr)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBER encodes TCInvokeIdSet to BER format.
func (v *TCInvokeIdSet) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		if int64(*v.Present) < -128 || int64(*v.Present) > 127 {
			return nil, fmt.Errorf("encoding TCInvokeIdSet violates WITH COMPONENTS: Present violates its value range")
		}
	}
	if v.Choice == TCInvokeIdSetChoiceAbsent {
		return nil, fmt.Errorf("encoding TCInvokeIdSet violates WITH COMPONENTS: Absent must be absent")
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
		if int64(*v.Present) < -128 || int64(*v.Present) > 127 {
			return nil, fmt.Errorf("encoding TCInvokeIdSet violates WITH COMPONENTS: Present violates its value range")
		}
	}
	if v.Choice == TCInvokeIdSetChoiceAbsent {
		return nil, fmt.Errorf("encoding TCInvokeIdSet violates WITH COMPONENTS: Absent must be absent")
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TCInvokeIdSet as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TCInvokeIdSet from BER/DER format.
func (v *TCInvokeIdSet) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: TCInvokeIdSet destination is nil", ber.ErrInvalidValue)
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
		return fmt.Errorf("decoding TCInvokeIdSet CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCInvokeIdSet", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = TCInvokeIdSetChoicePresent
		decVal, _, intErr := ber.DecodeInteger(choiceData, opts...)
		if intErr != nil {
			return fmt.Errorf("decoding present: %w", intErr)
		}
		v.Present = &decVal
		if !(int64(*v.Present) >= -128 && int64(*v.Present) <= 127) {
			if constraintErr := ber.CheckDecodedValue(opts, "present", "(-128..127)", fmt.Sprint(int64(*v.Present))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = TCInvokeIdSetChoiceAbsent
		_, nullErr := ber.DecodeNull(choiceData, opts...)
		if nullErr != nil {
			return fmt.Errorf("decoding absent: %w", nullErr)
		}
	} else {
		return fmt.Errorf("unknown tag %s for TCInvokeIdSet CHOICE", peekTag)
	}
	if v.Choice == TCInvokeIdSetChoicePresent {
		if v.Present == nil {
			return fmt.Errorf("decoded TCInvokeIdSet violates WITH COMPONENTS: Present must carry a constrained value")
		}
		if int64(*v.Present) < -128 || int64(*v.Present) > 127 {
			return fmt.Errorf("decoded TCInvokeIdSet violates WITH COMPONENTS: Present violates its value range")
		}
	}
	if v.Choice == TCInvokeIdSetChoiceAbsent {
		return fmt.Errorf("decoded TCInvokeIdSet violates WITH COMPONENTS: Absent must be absent")
	}
	return nil
}

// MarshalBER encodes AbortReason to BER format.
func (v *AbortReason) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
			return nil, fmt.Errorf("encoding p-abortCause: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case AbortReasonChoiceUAbortCause:
		if v.UAbortCause == nil {
			return nil, fmt.Errorf("%w: choice AbortReason: u-abortCause is nil", ber.ErrInvalidValue)
		}
		enc_1, extErr := v.UAbortCause.MarshalBER(opts...)
		if extErr != nil {
			return nil, fmt.Errorf("encoding u-abortCause: %w", extErr)
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
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AbortReason as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AbortReason from BER/DER format.
func (v *AbortReason) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AbortReason destination is nil", ber.ErrInvalidValue)
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
		return fmt.Errorf("decoding AbortReason CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AbortReason", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 10 && peekTag.Constructed == false {
		v.Choice = AbortReasonChoicePAbortCause
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding p-abortCause: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding p-abortCause: %w", intErr)
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

// MarshalBER encodes ComponentBasicROSInvokeLinkedId to BER format.
func (v *ComponentBasicROSInvokeLinkedId) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSInvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentBasicROSInvokeLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ComponentBasicROSInvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice ComponentBasicROSInvokeLinkedId: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding present: %w", encodeErr_enc_0)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding present: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ComponentBasicROSInvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding absent: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ComponentBasicROSInvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes ComponentBasicROSInvokeLinkedId to DER format.
func (v *ComponentBasicROSInvokeLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSInvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ComponentBasicROSInvokeLinkedId as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentBasicROSInvokeLinkedId from BER/DER format.
func (v *ComponentBasicROSInvokeLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentBasicROSInvokeLinkedId destination is nil", ber.ErrInvalidValue)
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
	*v = ComponentBasicROSInvokeLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ComponentBasicROSInvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ComponentBasicROSInvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding ComponentBasicROSInvokeLinkedId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentBasicROSInvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ComponentBasicROSInvokeLinkedIdChoicePresent
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding present: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding present: %w", intErr)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = ComponentBasicROSInvokeLinkedIdChoiceAbsent
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding absent: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding absent: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for ComponentBasicROSInvokeLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ComponentBasicROSReturnResultResult to BER format.
func (v *ComponentBasicROSReturnResultResult) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ComponentBasicROSReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(opts...)
	if err != nil {
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	children = append(children, enc_result...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ComponentBasicROSReturnResultResult to DER format.
func (v *ComponentBasicROSReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ComponentBasicROSReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ComponentBasicROSReturnResultResult as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentBasicROSReturnResultResult from BER/DER format.
func (v *ComponentBasicROSReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentBasicROSReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ComponentBasicROSReturnResultResult{}
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
		return fmt.Errorf("decoding ComponentBasicROSReturnResultResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentBasicROSReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	// Decode nested CHOICE (Code)
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opcode: %w", tlvErr_opcode)
	}
	if offset < 0 || offset >
		len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
		return fmt.Errorf("decoding opcode: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_opcode
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_result != nil {
		return fmt.Errorf("decoding result: %w", tlvErr_result)
	}
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
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ComponentBasicROSReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ComponentReturnResultNotLastResult to BER format.
func (v *ComponentReturnResultNotLastResult) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
	enc_opcode, err := v.Opcode.MarshalBER(opts...)
	if err != nil {
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
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
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ComponentReturnResultNotLastResult as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentReturnResultNotLastResult from BER/DER format.
func (v *ComponentReturnResultNotLastResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ComponentReturnResultNotLastResult destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ComponentReturnResultNotLastResult{}
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
		return fmt.Errorf("decoding ComponentReturnResultNotLastResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("missing required field opcode")
	}
	// Decode nested CHOICE (Code)
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opcode: %w", tlvErr_opcode)
	}
	if offset < 0 || offset >
		len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	if unmErr := v.Opcode.UnmarshalBER(content[offset:offset+n_opcode], ber.ChildDecodeOptions(opts, "opcode")...); unmErr != nil {
		return fmt.Errorf("decoding opcode: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_opcode < 0 || n_opcode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_opcode
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_result != nil {
		return fmt.Errorf("decoding result: %w", tlvErr_result)
	}
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
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ComponentReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}
