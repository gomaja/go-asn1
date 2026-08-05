// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

package tcap

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
	Components       ComponentPortion `asn1:"tag:12,application,implicit"`
	ComponentsIndef_ bool             `asn1:"-" json:"-"`
}

// Begin represents the ASN.1 type Begin (SEQUENCE).
type Begin struct {
	Otid             OrigTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       ComponentPortion  `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
}

// End represents the ASN.1 type End (SEQUENCE).
type End struct {
	Dtid             DestTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       ComponentPortion  `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
}

// Continue represents the ASN.1 type Continue (SEQUENCE).
type Continue struct {
	Otid             OrigTransactionID `asn1:""`
	Dtid             DestTransactionID `asn1:""`
	DialoguePortion  *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components       ComponentPortion  `asn1:"tag:12,application,implicit,optional" json:"Components,omitempty"`
	ComponentsIndef_ bool              `asn1:"-" json:"-"`
}

// Abort represents the ASN.1 type Abort (SEQUENCE).
type Abort struct {
	Dtid   DestTransactionID `asn1:""`
	Reason *AbortReason      `asn1:",optional" json:"Reason,omitempty"`
}

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
	BasicROS            *ROS `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ROS `json:"ReturnResultNotLast,omitempty"`
}

// NewComponentBasicROS creates a Component with the basicROS alternative.
func NewComponentBasicROS(v ROS) Component {
	return Component{
		Choice:   ComponentChoiceBasicROS,
		BasicROS: &v,
	}
}

// NewComponentReturnResultNotLast creates a Component with the returnResultNotLast alternative.
func NewComponentReturnResultNotLast(v ROS) Component {
	return Component{
		Choice:              ComponentChoiceReturnResultNotLast,
		ReturnResultNotLast: &v,
	}
}

// TCInvokeIdSet represents the ASN.1 type TCInvokeIdSet (CHOICE).
type TCInvokeIdSet = InvokeId

// AbortReason choice constants.
const (
	AbortReasonChoicePAbortCause = 1
	AbortReasonChoiceUAbortCause = 2
)

// AbortReason represents the ASN.1 CHOICE type Abort-reason.
type AbortReason struct {
	Choice      int
	PAbortCause *PAbortCause     `json:"PAbortCause,omitempty"`
	UAbortCause *DialoguePortion `json:"UAbortCause,omitempty"`
}

// NewAbortReasonPAbortCause creates a Abort-reason with the p-abortCause alternative.
func NewAbortReasonPAbortCause(v PAbortCause) AbortReason {
	return AbortReason{
		Choice:      AbortReasonChoicePAbortCause,
		PAbortCause: &v,
	}
}

// NewAbortReasonUAbortCause creates a Abort-reason with the u-abortCause alternative.
func NewAbortReasonUAbortCause(v DialoguePortion) AbortReason {
	return AbortReason{
		Choice:      AbortReasonChoiceUAbortCause,
		UAbortCause: &v,
	}
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

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 1 {
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
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 2 {
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
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 4 {
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
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 5 {
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
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 7 {
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
				_, n_dialogueportion, innerData_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
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
				_, n_dialogueportion, innerData_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
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
				_, n_dialogueportion, innerData_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
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
				_, n_dialogueportion, innerData_dialogueportion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dialoguePortion: %w", err)
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
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		return enc_1, nil
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

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
		v.Choice = ComponentChoiceReturnResultNotLast
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResultNotLast: %w", tlvErr)
		}
		var dec ROS
		if unmErr := dec.UnmarshalBER(innerData); unmErr != nil {
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
	return v.MarshalBER()
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

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 10 {
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
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 11 {
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
