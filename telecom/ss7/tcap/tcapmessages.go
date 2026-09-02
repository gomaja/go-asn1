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
	DialoguePortion  *DialoguePortion `asn1:",optional" json:"DialoguePortion,omitempty" asn1c:"raw-preserve"`
	Components       ComponentPortion `asn1:"tag:12,application,implicit"`
	ComponentsIndef_ bool             `asn1:"-" json:"-"`
}

// Begin represents the ASN.1 type Begin (SEQUENCE).
type Begin struct {
	Otid             OrigTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty" asn1c:"raw-preserve"`
	Components       ComponentPortion  `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
}

// End represents the ASN.1 type End (SEQUENCE).
type End struct {
	Dtid             DestTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty" asn1c:"raw-preserve"`
	Components       ComponentPortion  `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
}

// Continue represents the ASN.1 type Continue (SEQUENCE).
type Continue struct {
	Otid             OrigTransactionID `asn1:""`
	Dtid             DestTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty" asn1c:"raw-preserve"`
	Components       ComponentPortion  `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
}

// Abort represents the ASN.1 type Abort (SEQUENCE).
type Abort struct {
	Dtid   DestTransactionID `asn1:""`
	Reason *AbortReason      `asn1:",optional" json:"Reason,omitempty"`
}

// asn1c:raw-preserve
// DialoguePortion represents the ASN.1 type DialoguePortion (EXTERNAL).
type DialoguePortion = runtime.RawValue

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
type ComponentPortion = []Component

// Component choice constants.
const (
	ComponentChoiceBasicROS            = 1
	ComponentChoiceReturnResultNotLast = 2
)

// Component represents the ASN.1 CHOICE type Component.
type Component struct {
	Choice              int
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
	Choice  int
	Present *int64    `json:"Present,omitempty"`
	Absent  *struct{} `json:"Absent,omitempty"`
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
	Choice      int
	PAbortCause *PAbortCause     `json:"PAbortCause,omitempty"`
	UAbortCause *DialoguePortion `json:"UAbortCause,omitempty" asn1c:"raw-preserve"`
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
	Choice  int
	Present *big.Int  `json:"Present,omitempty"`
	Absent  *struct{} `json:"Absent,omitempty"`
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
	Opcode Code             `asn1:""`
	Result runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
}

// ComponentReturnResultNotLastResult represents the ASN.1 type Component-returnResultNotLast-result (SEQUENCE).
type ComponentReturnResultNotLastResult struct {
	Opcode Code             `asn1:""`
	Result runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
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
	switch v.Choice {
	case TCMessageChoiceUnidirectional:
		if v.Unidirectional == nil {
			return nil, fmt.Errorf("choice TCMessage: unidirectional is nil")
		}
		enc_der_0, err := v.Unidirectional.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding unidirectional: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 1, true, enc_der_0)
		if derErr := ber.ValidateDERElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding unidirectional as DER: %w", derErr)
		}
		return enc_der_0, nil
	case TCMessageChoiceBegin:
		if v.Begin == nil {
			return nil, fmt.Errorf("choice TCMessage: begin is nil")
		}
		enc_der_1, err := v.Begin.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding begin: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 2, true, enc_der_1)
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding begin as DER: %w", derErr)
		}
		return enc_der_1, nil
	case TCMessageChoiceEnd:
		if v.End == nil {
			return nil, fmt.Errorf("choice TCMessage: end is nil")
		}
		enc_der_2, err := v.End.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding end: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 4, true, enc_der_2)
		if derErr := ber.ValidateDERElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding end as DER: %w", derErr)
		}
		return enc_der_2, nil
	case TCMessageChoiceContinue:
		if v.Continue == nil {
			return nil, fmt.Errorf("choice TCMessage: continue is nil")
		}
		enc_der_3, err := v.Continue.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding continue: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 5, true, enc_der_3)
		if derErr := ber.ValidateDERElement(enc_der_3); derErr != nil {
			return nil, fmt.Errorf("encoding continue as DER: %w", derErr)
		}
		return enc_der_3, nil
	case TCMessageChoiceAbort:
		if v.Abort == nil {
			return nil, fmt.Errorf("choice TCMessage: abort is nil")
		}
		enc_der_4, err := v.Abort.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding abort: %w", err)
		}
		enc_der_4 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 7, true, enc_der_4)
		if derErr := ber.ValidateDERElement(enc_der_4); derErr != nil {
			return nil, fmt.Errorf("encoding abort as DER: %w", derErr)
		}
		return enc_der_4, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TCMessage as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TCMessage from BER/DER format.
func (v *TCMessage) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCMessage CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCMessage: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding TCMessage CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCMessage", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceUnidirectional
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding unidirectional: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Unidirectional
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding unidirectional: %w", unmErr)
		}
		v.Unidirectional = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceBegin
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding begin: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Begin
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding begin: %w", unmErr)
		}
		v.Begin = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceEnd
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding end: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec End
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding end: %w", unmErr)
		}
		v.End = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 5 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceContinue
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding continue: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Continue
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding continue: %w", unmErr)
		}
		v.Continue = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceAbort
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
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
		enc_dialogueportion := v.DialoguePortion.Bytes
		enc_dialogueportion = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 11, enc_dialogueportion)
		children = append(children, enc_dialogueportion...)
	}
	enc_components, err := MarshalBERComponentPortion(v.Components)
	if err != nil {
		return nil, fmt.Errorf("encoding components: %w", err)
	}
	if v.ComponentsIndef_ {
		indefTag_, _, indefContent_, tlvErr_ := ber.DecodeTLV(enc_components)
		if tlvErr_ != nil {
			return nil, tlvErr_
		}
		enc_components = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
	}
	children = append(children, enc_components...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Unidirectional to DER format.
func (v *Unidirectional) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ComponentsIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Unidirectional as DER: %w", err)
	}
	return encoded, nil
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
				decodedTag_dialogueportion, n_dialogueportion, innerData_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
				}
				if decodedTag_dialogueportion.Class != tag.ClassApplication || decodedTag_dialogueportion.Number != 11 || decodedTag_dialogueportion.Constructed != true {
					return fmt.Errorf("decoding dialoguePortion: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dialogueportion)
				}
				// Decode inner value from explicit tag wrapper
				tmp_dialogueportion := runtime.RawValue{Bytes: innerData_dialogueportion}
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
	v.ComponentsIndef_ = false
	// Decode nested SEQUENCE_OF (ComponentPortion)
	_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:])
	if tlvErr_components != nil {
		return fmt.Errorf("decoding components: %w", tlvErr_components)
	}
	tlv_components := content[offset : offset+n_components]
	{
		_, tagSz_, _ := ber.DecodeTag(tlv_components)
		if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
			v.ComponentsIndef_ = true
		}
	}
	dec_components, unmErr := UnmarshalBERComponentPortion(tlv_components)
	if unmErr != nil {
		return fmt.Errorf("decoding components: %w", unmErr)
	}
	v.Components = dec_components
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
		enc_dialogueportion := v.DialoguePortion.Bytes
		enc_dialogueportion = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 11, enc_dialogueportion)
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		enc_components, err := MarshalBERComponentPortion(v.Components)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		if v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_components = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Begin to DER format.
func (v *Begin) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ComponentsIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Begin as DER: %w", err)
	}
	return encoded, nil
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
	decodedTag_otid, n_otid, rawVal_otid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding otid: %w", err)
	}
	if decodedTag_otid.Class != tag.ClassApplication || decodedTag_otid.Number != 8 {
		return fmt.Errorf("decoding otid: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_otid)
	}
	v.Otid = OrigTransactionID(rawVal_otid)
	offset += n_otid
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				decodedTag_dialogueportion, n_dialogueportion, innerData_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
				}
				if decodedTag_dialogueportion.Class != tag.ClassApplication || decodedTag_dialogueportion.Number != 11 || decodedTag_dialogueportion.Constructed != true {
					return fmt.Errorf("decoding dialoguePortion: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dialogueportion)
				}
				// Decode inner value from explicit tag wrapper
				tmp_dialogueportion := runtime.RawValue{Bytes: innerData_dialogueportion}
				v.DialoguePortion = &tmp_dialogueportion
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
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:])
				if tlvErr_components != nil {
					return fmt.Errorf("decoding components: %w", tlvErr_components)
				}
				tlv_components := content[offset : offset+n_components]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_components)
					if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				dec_components, unmErr := UnmarshalBERComponentPortion(tlv_components)
				if unmErr != nil {
					return fmt.Errorf("decoding components: %w", unmErr)
				}
				v.Components = dec_components
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
		enc_dialogueportion := v.DialoguePortion.Bytes
		enc_dialogueportion = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 11, enc_dialogueportion)
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		enc_components, err := MarshalBERComponentPortion(v.Components)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		if v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_components = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes End to DER format.
func (v *End) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ComponentsIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding End as DER: %w", err)
	}
	return encoded, nil
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
	decodedTag_dtid, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dtid: %w", err)
	}
	if decodedTag_dtid.Class != tag.ClassApplication || decodedTag_dtid.Number != 9 {
		return fmt.Errorf("decoding dtid: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dtid)
	}
	v.Dtid = DestTransactionID(rawVal_dtid)
	offset += n_dtid
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				decodedTag_dialogueportion, n_dialogueportion, innerData_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
				}
				if decodedTag_dialogueportion.Class != tag.ClassApplication || decodedTag_dialogueportion.Number != 11 || decodedTag_dialogueportion.Constructed != true {
					return fmt.Errorf("decoding dialoguePortion: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dialogueportion)
				}
				// Decode inner value from explicit tag wrapper
				tmp_dialogueportion := runtime.RawValue{Bytes: innerData_dialogueportion}
				v.DialoguePortion = &tmp_dialogueportion
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
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:])
				if tlvErr_components != nil {
					return fmt.Errorf("decoding components: %w", tlvErr_components)
				}
				tlv_components := content[offset : offset+n_components]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_components)
					if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				dec_components, unmErr := UnmarshalBERComponentPortion(tlv_components)
				if unmErr != nil {
					return fmt.Errorf("decoding components: %w", unmErr)
				}
				v.Components = dec_components
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
		enc_dialogueportion := v.DialoguePortion.Bytes
		enc_dialogueportion = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 11, enc_dialogueportion)
		children = append(children, enc_dialogueportion...)
	}
	if v.Components != nil {
		enc_components, err := MarshalBERComponentPortion(v.Components)
		if err != nil {
			return nil, fmt.Errorf("encoding components: %w", err)
		}
		if v.ComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_components = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
		}
		children = append(children, enc_components...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes Continue to DER format.
func (v *Continue) MarshalDER() ([]byte, error) {
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ComponentsIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Continue as DER: %w", err)
	}
	return encoded, nil
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
	decodedTag_otid, n_otid, rawVal_otid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding otid: %w", err)
	}
	if decodedTag_otid.Class != tag.ClassApplication || decodedTag_otid.Number != 8 {
		return fmt.Errorf("decoding otid: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_otid)
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
	decodedTag_dtid, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dtid: %w", err)
	}
	if decodedTag_dtid.Class != tag.ClassApplication || decodedTag_dtid.Number != 9 {
		return fmt.Errorf("decoding dtid: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dtid)
	}
	v.Dtid = DestTransactionID(rawVal_dtid)
	offset += n_dtid
	// Decode dialoguePortion
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
				decodedTag_dialogueportion, n_dialogueportion, innerData_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
				}
				if decodedTag_dialogueportion.Class != tag.ClassApplication || decodedTag_dialogueportion.Number != 11 || decodedTag_dialogueportion.Constructed != true {
					return fmt.Errorf("decoding dialoguePortion: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dialogueportion)
				}
				// Decode inner value from explicit tag wrapper
				tmp_dialogueportion := runtime.RawValue{Bytes: innerData_dialogueportion}
				v.DialoguePortion = &tmp_dialogueportion
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
				_, n_components, _, tlvErr_components := ber.DecodeTLV(content[offset:])
				if tlvErr_components != nil {
					return fmt.Errorf("decoding components: %w", tlvErr_components)
				}
				tlv_components := content[offset : offset+n_components]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_components)
					if tagSz_ < len(tlv_components) && tlv_components[tagSz_] == 0x80 {
						v.ComponentsIndef_ = true
					}
				}
				dec_components, unmErr := UnmarshalBERComponentPortion(tlv_components)
				if unmErr != nil {
					return fmt.Errorf("decoding components: %w", unmErr)
				}
				v.Components = dec_components
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
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Abort as DER: %w", err)
	}
	return encoded, nil
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
	decodedTag_dtid, n_dtid, rawVal_dtid, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding dtid: %w", err)
	}
	if decodedTag_dtid.Class != tag.ClassApplication || decodedTag_dtid.Number != 9 {
		return fmt.Errorf("decoding dtid: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dtid)
	}
	v.Dtid = DestTransactionID(rawVal_dtid)
	offset += n_dtid
	// Decode reason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassApplication && peekTag.Number == 10) || (peekTag.Class == tag.ClassApplication && peekTag.Number == 11) {
				// Decode nested CHOICE (AbortReason)
				_, n_reason, _, tlvErr_reason := ber.DecodeTLV(content[offset:])
				if tlvErr_reason != nil {
					return fmt.Errorf("decoding reason: %w", tlvErr_reason)
				}
				var dec_reason AbortReason
				if unmErr := dec_reason.UnmarshalBER(content[offset : offset+n_reason]); unmErr != nil {
					return fmt.Errorf("decoding reason: %w", unmErr)
				}
				v.Reason = &dec_reason
				offset += n_reason
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "Abort", Cause: ber.ErrExtraData}
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
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 12, Constructed: true}, children), nil
}

// UnmarshalBERComponentPortion decodes a ComponentPortion list from BER.
func UnmarshalBERComponentPortion(data []byte) (ComponentPortion, error) {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ComponentPortion: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 12 || !decodedTag.Constructed {
		return nil, fmt.Errorf("decoding ComponentPortion: %w: expected tag [APPLICATION 12], got %s", ber.ErrInvalidTag, decodedTag)
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
	case ComponentChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("choice Component: basicROS is nil")
		}
		enc_0, err := v.BasicROS.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicROS: %w", err)
		}
		return enc_0, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("choice Component: returnResultNotLast is nil")
		}
		enc_1, err := v.ReturnResultNotLast.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Component", v.Choice)
	}
}

// MarshalDER encodes Component to DER format.
func (v *Component) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ComponentChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("choice Component: basicROS is nil")
		}
		enc_der_0, err := v.BasicROS.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicROS: %w", err)
		}
		if derErr := ber.ValidateDERElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding basicROS as DER: %w", derErr)
		}
		return enc_der_0, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("choice Component: returnResultNotLast is nil")
		}
		enc_der_1, err := v.ReturnResultNotLast.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_der_1)
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding returnResultNotLast as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Component as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Component from BER/DER format.
func (v *Component) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Component CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Component: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Component CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Component", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = ComponentChoiceReturnResultNotLast
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
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
		v.Choice = ComponentChoiceBasicROS
		var dec ROS
		if unmErr := dec.UnmarshalBER(choiceData); unmErr != nil {
			return fmt.Errorf("decoding basicROS: %w", unmErr)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBER encodes TCInvokeIdSet to BER format.
func (v *TCInvokeIdSet) MarshalBER() ([]byte, error) {
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
			return nil, fmt.Errorf("choice TCInvokeIdSet: present is nil")
		}
		enc_0 := ber.EncodeInteger(int64(*v.Present))
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
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding TCInvokeIdSet as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes TCInvokeIdSet from BER/DER format.
func (v *TCInvokeIdSet) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for TCInvokeIdSet CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for TCInvokeIdSet: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding TCInvokeIdSet CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "TCInvokeIdSet", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = TCInvokeIdSetChoicePresent
		decVal, _, intErr := ber.DecodeInteger(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding present: %w", intErr)
		}
		v.Present = &decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = TCInvokeIdSetChoiceAbsent
		_, nullErr := ber.DecodeNull(choiceData)
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
func (v *AbortReason) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AbortReasonChoicePAbortCause:
		if v.PAbortCause == nil {
			return nil, fmt.Errorf("choice AbortReason: p-abortCause is nil")
		}
		enc_0 := ber.EncodeInteger(int64(*v.PAbortCause))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 10, false, enc_0)
		return enc_0, nil
	case AbortReasonChoiceUAbortCause:
		if v.UAbortCause == nil {
			return nil, fmt.Errorf("choice AbortReason: u-abortCause is nil")
		}
		enc_1 := v.UAbortCause.Bytes
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassApplication, 11, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AbortReason", v.Choice)
	}
}

// MarshalDER encodes AbortReason to DER format.
func (v *AbortReason) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AbortReason as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AbortReason from BER/DER format.
func (v *AbortReason) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AbortReason CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AbortReason: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AbortReason CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AbortReason", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 10 && peekTag.Constructed == false {
		v.Choice = AbortReasonChoicePAbortCause
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding p-abortCause: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding p-abortCause: %w", intErr)
		}
		tmp := PAbortCause(decVal)
		v.PAbortCause = &tmp
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 && peekTag.Constructed == true {
		v.Choice = AbortReasonChoiceUAbortCause
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding u-abortCause: %w", tlvErr)
		}
		tmpRaw := runtime.RawValue{Bytes: innerData}
		v.UAbortCause = &tmpRaw
	} else {
		return fmt.Errorf("unknown tag %s for AbortReason CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ComponentBasicROSInvokeLinkedId to BER format.
func (v *ComponentBasicROSInvokeLinkedId) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ComponentBasicROSInvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("choice ComponentBasicROSInvokeLinkedId: present is nil")
		}
		enc_0 := ber.EncodeBigInt(v.Present)
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case ComponentBasicROSInvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ComponentBasicROSInvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes ComponentBasicROSInvokeLinkedId to DER format.
func (v *ComponentBasicROSInvokeLinkedId) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ComponentBasicROSInvokeLinkedId as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentBasicROSInvokeLinkedId from BER/DER format.
func (v *ComponentBasicROSInvokeLinkedId) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ComponentBasicROSInvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ComponentBasicROSInvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ComponentBasicROSInvokeLinkedId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ComponentBasicROSInvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ComponentBasicROSInvokeLinkedIdChoicePresent
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
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
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
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
func (v *ComponentBasicROSReturnResultResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	children = append(children, enc_result...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ComponentBasicROSReturnResultResult to DER format.
func (v *ComponentBasicROSReturnResultResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ComponentBasicROSReturnResultResult as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentBasicROSReturnResultResult from BER/DER format.
func (v *ComponentBasicROSReturnResultResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:])
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opcode: %w", tlvErr_opcode)
	}
	if unmErr := v.Opcode.UnmarshalBER(content[offset : offset+n_opcode]); unmErr != nil {
		return fmt.Errorf("decoding opcode: %w", unmErr)
	}
	offset += n_opcode
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:])
	if tlvErr_result != nil {
		return fmt.Errorf("decoding result: %w", tlvErr_result)
	}
	v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
	offset += n_result
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ComponentBasicROSReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ComponentReturnResultNotLastResult to BER format.
func (v *ComponentReturnResultNotLastResult) MarshalBER() ([]byte, error) {
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	children = append(children, enc_result...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ComponentReturnResultNotLastResult to DER format.
func (v *ComponentReturnResultNotLastResult) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ComponentReturnResultNotLastResult as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ComponentReturnResultNotLastResult from BER/DER format.
func (v *ComponentReturnResultNotLastResult) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	_, n_opcode, _, tlvErr_opcode := ber.DecodeTLV(content[offset:])
	if tlvErr_opcode != nil {
		return fmt.Errorf("decoding opcode: %w", tlvErr_opcode)
	}
	if unmErr := v.Opcode.UnmarshalBER(content[offset : offset+n_opcode]); unmErr != nil {
		return fmt.Errorf("decoding opcode: %w", unmErr)
	}
	offset += n_opcode
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	_, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:])
	if tlvErr_result != nil {
		return fmt.Errorf("decoding result: %w", tlvErr_result)
	}
	v.Result = runtime.RawValue{Bytes: content[offset : offset+n_result]}
	offset += n_result
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ComponentReturnResultNotLastResult", Cause: ber.ErrExtraData}
	}
	return nil
}
