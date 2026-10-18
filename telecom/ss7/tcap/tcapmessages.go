// Code generated from ASN.1 module "TCAPMessages". DO NOT EDIT.

package tcap

import (
	"fmt"
	"math/big"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
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
	berReplayNode_ *ber.ReplayNode `json:"-"`
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
	DialoguePortion     *DialoguePortion `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components          ComponentPortion `asn1:""`
	berComponentsIndef_ bool             `asn1:"-" json:"-"`
	berReplayNode_      *ber.ReplayNode  `asn1:"-" json:"-"`
}

// Begin represents the ASN.1 type Begin (SEQUENCE).
type Begin struct {
	Otid                OrigTransactionID `asn1:""`
	DialoguePortion     *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components          *ComponentPortion `asn1:",optional" json:"Components,omitempty"`
	berComponentsIndef_ bool              `asn1:"-" json:"-"`
	berReplayNode_      *ber.ReplayNode   `asn1:"-" json:"-"`
}

// End represents the ASN.1 type End (SEQUENCE).
type End struct {
	Dtid                DestTransactionID `asn1:""`
	DialoguePortion     *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components          *ComponentPortion `asn1:",optional" json:"Components,omitempty"`
	berComponentsIndef_ bool              `asn1:"-" json:"-"`
	berReplayNode_      *ber.ReplayNode   `asn1:"-" json:"-"`
}

// Continue represents the ASN.1 type Continue (SEQUENCE).
type Continue struct {
	Otid                OrigTransactionID `asn1:""`
	Dtid                DestTransactionID `asn1:""`
	DialoguePortion     *DialoguePortion  `asn1:",optional" json:"DialoguePortion,omitempty"`
	Components          *ComponentPortion `asn1:",optional" json:"Components,omitempty"`
	berComponentsIndef_ bool              `asn1:"-" json:"-"`
	berReplayNode_      *ber.ReplayNode   `asn1:"-" json:"-"`
}

// Abort represents the ASN.1 type Abort (SEQUENCE).
type Abort struct {
	Dtid           DestTransactionID `asn1:""`
	Reason         *AbortReason      `asn1:",optional" json:"Reason,omitempty"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// DialoguePortion represents the ASN.1 EXTERNAL type DialoguePortion.

// OrigTransactionID represents the ASN.1 type OrigTransactionID (OCTET_STRING).
type OrigTransactionID []byte

// DestTransactionID represents the ASN.1 type DestTransactionID (OCTET_STRING).
type DestTransactionID []byte

// PAbortCause represents the arbitrary-width ASN.1 INTEGER type P-AbortCause with named numbers.
type PAbortCause struct {
	noCompare [0]func()
	value     *big.Int
}

const (
	PAbortCauseUnrecognizedMessageTypeDecimal          = "0"
	PAbortCauseUnrecognizedMessageType                 = 0
	PAbortCauseUnrecognizedTransactionIDDecimal        = "1"
	PAbortCauseUnrecognizedTransactionID               = 1
	PAbortCauseBadlyFormattedTransactionPortionDecimal = "2"
	PAbortCauseBadlyFormattedTransactionPortion        = 2
	PAbortCauseIncorrectTransactionPortionDecimal      = "3"
	PAbortCauseIncorrectTransactionPortion             = 3
	PAbortCauseResourceLimitationDecimal               = "4"
	PAbortCauseResourceLimitation                      = 4
)

// NewPAbortCause returns an immutable PAbortCause containing value.
func NewPAbortCause(value *big.Int) PAbortCause {
	return PAbortCause{value: runtime.CloneBigInt(value)}
}

// NewPAbortCauseInt64 returns a PAbortCause containing value.
func NewPAbortCauseInt64(value int64) PAbortCause {
	return NewPAbortCause(big.NewInt(value))
}

// PAbortCauseUnrecognizedMessageTypeValue returns the named value unrecognizedMessageType.
func PAbortCauseUnrecognizedMessageTypeValue() PAbortCause {
	return NewPAbortCause(runtime.MustParseBigIntDecimal(PAbortCauseUnrecognizedMessageTypeDecimal))
}

// PAbortCauseUnrecognizedTransactionIDValue returns the named value unrecognizedTransactionID.
func PAbortCauseUnrecognizedTransactionIDValue() PAbortCause {
	return NewPAbortCause(runtime.MustParseBigIntDecimal(PAbortCauseUnrecognizedTransactionIDDecimal))
}

// PAbortCauseBadlyFormattedTransactionPortionValue returns the named value badlyFormattedTransactionPortion.
func PAbortCauseBadlyFormattedTransactionPortionValue() PAbortCause {
	return NewPAbortCause(runtime.MustParseBigIntDecimal(PAbortCauseBadlyFormattedTransactionPortionDecimal))
}

// PAbortCauseIncorrectTransactionPortionValue returns the named value incorrectTransactionPortion.
func PAbortCauseIncorrectTransactionPortionValue() PAbortCause {
	return NewPAbortCause(runtime.MustParseBigIntDecimal(PAbortCauseIncorrectTransactionPortionDecimal))
}

// PAbortCauseResourceLimitationValue returns the named value resourceLimitation.
func PAbortCauseResourceLimitationValue() PAbortCause {
	return NewPAbortCause(runtime.MustParseBigIntDecimal(PAbortCauseResourceLimitationDecimal))
}

// BigInt returns an independent arbitrary-precision copy of v.
func (v PAbortCause) BigInt() *big.Int {
	return runtime.CloneBigInt(v.value)
}

// AsInt64 returns v when it is representable as int64.
func (v PAbortCause) AsInt64() (int64, bool) {
	value := v.BigInt()
	if !value.IsInt64() {
		return 0, false
	}
	return value.Int64(), true
}

// Name returns the ASN.1 named-number label for v when one exists.
func (v PAbortCause) Name() (string, bool) {
	switch v.BigInt().String() {
	case PAbortCauseUnrecognizedMessageTypeDecimal:
		return "unrecognizedMessageType", true
	case PAbortCauseUnrecognizedTransactionIDDecimal:
		return "unrecognizedTransactionID", true
	case PAbortCauseBadlyFormattedTransactionPortionDecimal:
		return "badlyFormattedTransactionPortion", true
	case PAbortCauseIncorrectTransactionPortionDecimal:
		return "incorrectTransactionPortion", true
	case PAbortCauseResourceLimitationDecimal:
		return "resourceLimitation", true
	default:
		return "", false
	}
}

func (v PAbortCause) String() string {
	if name, ok := v.Name(); ok {
		return name
	}
	return v.BigInt().String()
}

// MarshalText returns the exact decimal INTEGER value.
func (v PAbortCause) MarshalText() ([]byte, error) {
	return []byte(v.BigInt().String()), nil
}

// UnmarshalText replaces v with an exact decimal INTEGER value.
func (v *PAbortCause) UnmarshalText(text []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal PAbortCause into nil receiver")
	}
	value, err := runtime.ParseBigIntDecimal(string(text))
	if err != nil {
		return err
	}
	*v = NewPAbortCause(value)
	return nil
}

// MarshalJSON returns the exact decimal INTEGER value as a JSON string.
func (v PAbortCause) MarshalJSON() ([]byte, error) {
	return runtime.MarshalBigIntJSON(v.BigInt())
}

// UnmarshalJSON accepts an exact decimal JSON string or number.
func (v *PAbortCause) UnmarshalJSON(data []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal PAbortCause into nil receiver")
	}
	value, err := runtime.UnmarshalBigIntJSON(data)
	if err != nil {
		return err
	}
	*v = NewPAbortCause(value)
	return nil
}

// ComponentPortion represents the ASN.1 type ComponentPortion (SEQUENCE_OF).
type ComponentPortion struct {
	Values         []Component     `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// Component choice constants.
const (
	ComponentChoiceBasicROS            = 1
	ComponentChoiceReturnResultNotLast = 2
)

// Component represents the ASN.1 CHOICE type Component.
type Component struct {
	Choice              int
	berReplayNode_      *ber.ReplayNode `json:"-"`
	BasicROS            *ROS            `json:"BasicROS,omitempty"`
	ReturnResultNotLast *ReturnResult   `json:"ReturnResultNotLast,omitempty"`
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
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Present        *big.Int        `json:"Present,omitempty"`
	Absent         *struct{}       `json:"Absent,omitempty"`
}

// NewTCInvokeIdSetPresent creates a TCInvokeIdSet with the present alternative.
func NewTCInvokeIdSetPresent(v *big.Int) TCInvokeIdSet {
	return TCInvokeIdSet{
		Choice:  TCInvokeIdSetChoicePresent,
		Present: v,
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
	Choice         int
	berReplayNode_ *ber.ReplayNode  `json:"-"`
	PAbortCause    *PAbortCause     `json:"PAbortCause,omitempty"`
	UAbortCause    *DialoguePortion `json:"UAbortCause,omitempty"`
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

// MarshalBER encodes TCMessage to BER format.
func (v *TCMessage) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "TCMessage", "TCAPMessages", "TCMessage")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: TCMessage receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) && (v.Choice == TCMessageChoiceUnidirectional || v.Choice == TCMessageChoiceBegin || v.Choice == TCMessageChoiceEnd || v.Choice == TCMessageChoiceContinue || v.Choice == TCMessageChoiceAbort) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *TCMessage) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: TCMessage receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	switch v.Choice {
	case TCMessageChoiceUnidirectional:
		if v.Unidirectional == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: unidirectional is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassApplication, Number: 1}, false)
		_, err := v.Unidirectional.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "unidirectional")...)
		if err != nil {
			return nil, qualifyBERError(err, "unidirectional", "encoding", true)
		}
		return nil, nil
	case TCMessageChoiceBegin:
		if v.Begin == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: begin is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassApplication, Number: 2}, false)
		_, err := v.Begin.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "begin")...)
		if err != nil {
			return nil, qualifyBERError(err, "begin", "encoding", true)
		}
		return nil, nil
	case TCMessageChoiceEnd:
		if v.End == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: end is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassApplication, Number: 4}, false)
		_, err := v.End.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "end")...)
		if err != nil {
			return nil, qualifyBERError(err, "end", "encoding", true)
		}
		return nil, nil
	case TCMessageChoiceContinue:
		if v.Continue == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: continue is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassApplication, Number: 5}, false)
		_, err := v.Continue.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "continue")...)
		if err != nil {
			return nil, qualifyBERError(err, "continue", "encoding", true)
		}
		return nil, nil
	case TCMessageChoiceAbort:
		if v.Abort == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: abort is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassApplication, Number: 7}, false)
		_, err := v.Abort.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "abort")...)
		if err != nil {
			return nil, qualifyBERError(err, "abort", "encoding", true)
		}
		return nil, nil
	default:
		encoded, err := v.marshalBER(opts...)
		if err != nil {
			return nil, err
		}
		encoder.Append(encoded)
		return nil, nil
	}
}
func (v *TCMessage) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
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
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: TCMessage receiver is nil", ber.ErrInvalidValue)
	}
	if v.Choice == TCMessageChoiceUnidirectional || v.Choice == TCMessageChoiceBegin || v.Choice == TCMessageChoiceEnd || v.Choice == TCMessageChoiceContinue || v.Choice == TCMessageChoiceAbort {
		encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendDERLinear(encoder)
			return appendErr
		})
		if err != nil {
			return nil, err
		}
		return encoded, nil
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

func (v *TCMessage) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: TCMessage receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case TCMessageChoiceUnidirectional:
		if v.Unidirectional == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: unidirectional is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassApplication, Number: 1}, false)
		_, err := v.Unidirectional.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "unidirectional", "encoding", true)
		}
		return nil, nil
	case TCMessageChoiceBegin:
		if v.Begin == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: begin is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassApplication, Number: 2}, false)
		_, err := v.Begin.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "begin", "encoding", true)
		}
		return nil, nil
	case TCMessageChoiceEnd:
		if v.End == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: end is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassApplication, Number: 4}, false)
		_, err := v.End.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "end", "encoding", true)
		}
		return nil, nil
	case TCMessageChoiceContinue:
		if v.Continue == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: continue is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassApplication, Number: 5}, false)
		_, err := v.Continue.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "continue", "encoding", true)
		}
		return nil, nil
	case TCMessageChoiceAbort:
		if v.Abort == nil {
			return nil, fmt.Errorf("%w: choice TCMessage: abort is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassApplication, Number: 7}, false)
		_, err := v.Abort.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "abort", "encoding", true)
		}
		return nil, nil
	default:
		encoded, err := v.MarshalDER()
		if err != nil {
			return nil, err
		}
		encoder.Append(encoded)
		return nil, nil
	}
}

// UnmarshalBER decodes TCMessage from BER/DER format.
func (destination *TCMessage) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	originalInput := data
	defer func() {
		if returnErr !=

			nil {
			returnErr =
				locateTCAPDecodeError(returnErr,

					originalInput)
		}
	}()
	if destination == nil {
		return fmt.Errorf("nil TCMessage destination")
	}
	var next TCMessage
	v :=

		&next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "TCMessage", "TCAPMessages", "TCMessage")
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *TCMessage, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCMessage
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "TCAPMessages.TCMessage", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
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

	if (peekTag.Class == tag.ClassApplication && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "TCMessage.unidirectional", "decoding", false)
	}
	if (peekTag.Class == tag.ClassApplication && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "TCMessage.begin", "decoding", false)
	}
	if (peekTag.Class == tag.ClassApplication && peekTag.Number == 4) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "TCMessage.end", "decoding", false)
	}
	if (peekTag.Class == tag.ClassApplication && peekTag.Number == 5) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "TCMessage.continue", "decoding", false)
	}
	if (peekTag.Class == tag.ClassApplication && peekTag.Number == 7) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "TCMessage.abort", "decoding", false)
	}
	if peekTag.Class == tag.ClassApplication && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = TCMessageChoiceUnidirectional
		ber.MarkPreflightTarget(opts, "unidirectional", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "unidirectional", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Unidirectional
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
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Begin
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
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec End
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
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Continue
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
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
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
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err

	}

	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "Unidirectional", "TCAPMessages", "Unidirectional")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: Unidirectional receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *Unidirectional) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	var children []byte
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", false)
		}
		children = append(children, enc_dialogueportion...)
	}

	if len((v.Components).Values) < 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Unidirectional"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_components, err := tcapMarshalBERComponentPortion(&v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
	if err != nil {
		return nil, qualifyBERError(err, "components", "encoding", false)
	}
	if ber.BERReplayEnabled(opts) && v.berComponentsIndef_ {
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
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_components)
	children = append(children, enc_components...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *Unidirectional) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err

	}

	if v == nil {
		return nil, fmt.Errorf("%w: Unidirectional receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildGeneratedEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		encoder.Append(enc_dialogueportion)
	}
	if v.berComponentsIndef_ && ber.BERGeneratedReplayEnabled(opts) {

		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Unidirectional"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := tcapMarshalBERComponentPortion(&v.Components, ber.ParentGeneratedCollectionSizeEncodeOptions(ber.ChildGeneratedEncodeOptions(opts, "components"))...)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", true)
		}
		if ber.BERGeneratedReplayEnabled(opts) && v.berComponentsIndef_ {
			indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "Components", "encoding", true)
				}
			}
		}
		encoder.Append(enc_components)
	} else {
		{

			if len((v.Components).Values) < 1 {
				if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Unidirectional"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
					return nil, constraintErr
				}
			}
			_, err := appendBERLinearComponentPortion(encoder, &v.Components, ber.ParentGeneratedCollectionSizeEncodeOptions(ber.ChildGeneratedEncodeOptions(opts, "components"))...)
			if err != nil {
				return nil, qualifyBERError(err, "components", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes Unidirectional to DER format.
func (v *Unidirectional) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Unidirectional receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := v.appendDERLinear(encoder)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *Unidirectional) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Unidirectional receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		encoder.Append(enc_dialogueportion)
	}
	{

		if len((v.Components).Values) < 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(nil, "TCAPMessages.Unidirectional"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		_, err := appendDERLinearComponentPortion(encoder, &v.Components)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", true)
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes Unidirectional from BER/DER format.
func (destination *Unidirectional) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil Unidirectional destination")
	}
	var next Unidirectional

	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "Unidirectional", "TCAPMessages", "Unidirectional")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Unidirectional
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "TCAPMessages.Unidirectional", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Unidirectional{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *Unidirectional, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
		v.berComponentsIndef_ = false
		ber.MarkPreflightTarget(opts, "components", content[offset:])
		// Decode nested SEQUENCE_OF (ComponentPortion)
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
				v.berComponentsIndef_ = true
			}
		}
		dec_components, unmErr := tcapUnmarshalBERComponentPortion(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "components", "decoding", false)
		}
		v.Components = *dec_components
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
	if ruleErr := v.checkTCAPDecodedRules(opts); ruleErr !=
		nil {
		return ruleErr
	}

	return nil
}

// MarshalBER encodes Begin to BER format.
func (v *Begin) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err

	}

	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "Begin", "TCAPMessages", "Begin")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: Begin receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *Begin) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	var children []byte
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Begin"), "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Begin"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := tcapMarshalBERComponentPortion(v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berComponentsIndef_ {
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_components)
		children = append(children, enc_components...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *Begin) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err

	}

	if v == nil {
		return nil, fmt.Errorf("%w: Begin receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Begin"), "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
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
	encoder.Append(enc_otid)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildGeneratedEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		encoder.Append(enc_dialogueportion)
	}
	if v.Components != nil {
		if v.berComponentsIndef_ && ber.BERGeneratedReplayEnabled(opts) {
			if len((v.Components).Values) < 1 {
				if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Begin"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
					return nil, constraintErr
				}
			}
			enc_components, err := tcapMarshalBERComponentPortion(v.Components, ber.ParentGeneratedCollectionSizeEncodeOptions(ber.ChildGeneratedEncodeOptions(opts, "components"))...)
			if err != nil {
				return nil, qualifyBERError(err, "components", "encoding", true)
			}
			if ber.BERGeneratedReplayEnabled(opts) && v.berComponentsIndef_ {
				indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
				if tlvErr_ != nil {
					return nil, tlvErr_
				}
				{
					var encodeErr error
					enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
					if encodeErr != nil {
						return nil, qualifyBERError(encodeErr, "Components", "encoding", true)
					}
				}
			}
			encoder.Append(enc_components)
		} else {
			{
				if len((v.Components).Values) < 1 {
					if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Begin"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
						return nil, constraintErr
					}
				}
				_, err := appendBERLinearComponentPortion(encoder, v.Components, ber.ParentGeneratedCollectionSizeEncodeOptions(ber.ChildGeneratedEncodeOptions(opts, "components"))...)
				if err != nil {
					return nil, qualifyBERError(err, "components", "encoding", true)
				}
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes Begin to DER format.
func (v *Begin) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Begin receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := v.appendDERLinear(encoder)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *Begin) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Begin receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(nil, "TCAPMessages.Begin"), "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
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
	encoder.Append(enc_otid)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		encoder.Append(enc_dialogueportion)
	}
	if v.Components != nil {
		{
			if len((v.Components).Values) < 1 {
				if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(nil, "TCAPMessages.Begin"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
					return nil, constraintErr
				}
			}
			_, err := appendDERLinearComponentPortion(encoder, v.Components)
			if err != nil {
				return nil, qualifyBERError(err, "components", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes Begin from BER/DER format.
func (destination *Begin) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil Begin destination")
	}
	var next Begin
	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "Begin", "TCAPMessages", "Begin")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Begin
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "TCAPMessages.Begin", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Begin{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *Begin, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
	v.berComponentsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "components", content[offset:])
				// Decode nested SEQUENCE_OF (ComponentPortion)
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
						v.berComponentsIndef_ = true
					}
				}
				dec_components, unmErr := tcapUnmarshalBERComponentPortion(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
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
	if ruleErr := v.checkTCAPDecodedRules(opts); ruleErr !=
		nil {
		return ruleErr
	}

	return nil
}

// MarshalBER encodes End to BER format.
func (v *End) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err

	}

	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "End", "TCAPMessages", "End")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: End receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *End) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	var children []byte
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.End"), "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.End"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := tcapMarshalBERComponentPortion(v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berComponentsIndef_ {
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_components)
		children = append(children, enc_components...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *End) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err

	}

	if v == nil {
		return nil, fmt.Errorf("%w: End receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.End"), "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
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
	encoder.Append(enc_dtid)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildGeneratedEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		encoder.Append(enc_dialogueportion)
	}
	if v.Components != nil {
		if v.berComponentsIndef_ && ber.BERGeneratedReplayEnabled(opts) {
			if len((v.Components).Values) < 1 {
				if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.End"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
					return nil, constraintErr
				}
			}
			enc_components, err := tcapMarshalBERComponentPortion(v.Components, ber.ParentGeneratedCollectionSizeEncodeOptions(ber.ChildGeneratedEncodeOptions(opts, "components"))...)
			if err != nil {
				return nil, qualifyBERError(err, "components", "encoding", true)
			}
			if ber.BERGeneratedReplayEnabled(opts) && v.berComponentsIndef_ {
				indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
				if tlvErr_ != nil {
					return nil, tlvErr_
				}
				{
					var encodeErr error
					enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
					if encodeErr != nil {
						return nil, qualifyBERError(encodeErr, "Components", "encoding", true)
					}
				}
			}
			encoder.Append(enc_components)
		} else {
			{
				if len((v.Components).Values) < 1 {
					if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.End"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
						return nil, constraintErr
					}
				}
				_, err := appendBERLinearComponentPortion(encoder, v.Components, ber.ParentGeneratedCollectionSizeEncodeOptions(ber.ChildGeneratedEncodeOptions(opts, "components"))...)
				if err != nil {
					return nil, qualifyBERError(err, "components", "encoding", true)
				}
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes End to DER format.
func (v *End) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: End receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := v.appendDERLinear(encoder)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *End) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: End receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(nil, "TCAPMessages.End"), "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
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
	encoder.Append(enc_dtid)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		encoder.Append(enc_dialogueportion)
	}
	if v.Components != nil {
		{
			if len((v.Components).Values) < 1 {
				if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(nil, "TCAPMessages.End"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
					return nil, constraintErr
				}
			}
			_, err := appendDERLinearComponentPortion(encoder, v.Components)
			if err != nil {
				return nil, qualifyBERError(err, "components", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes End from BER/DER format.
func (destination *End) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil End destination")
	}
	var next End
	v :=
		&next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "End", "TCAPMessages", "End")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error { var probe End; return probe.UnmarshalBER(data, probeOpts...) })
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "TCAPMessages.End", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = End{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *End, replayOpts ...ber.EncodeOption) ([]byte, error) { return base.MarshalBER(replayOpts...) })
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
	v.berComponentsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "components", content[offset:])
				// Decode nested SEQUENCE_OF (ComponentPortion)
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
						v.berComponentsIndef_ = true
					}
				}
				dec_components, unmErr := tcapUnmarshalBERComponentPortion(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
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
	if ruleErr := v.checkTCAPDecodedRules(opts); ruleErr !=
		nil {
		return ruleErr
	}

	return nil
}

// MarshalBER encodes Continue to BER format.
func (v *Continue) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err

	}

	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "Continue", "TCAPMessages", "Continue")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: Continue receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *Continue) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	var children []byte
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Continue"), "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
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
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Continue"), "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Continue"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_components, err := tcapMarshalBERComponentPortion(v.Components, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "components"))...)
		if err != nil {
			return nil, qualifyBERError(err, "components", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berComponentsIndef_ {
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_components)
		children = append(children, enc_components...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *Continue) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err

	}

	if v == nil {
		return nil, fmt.Errorf("%w: Continue receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Continue"), "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
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
	encoder.Append(enc_otid)
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Continue"), "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
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
	encoder.Append(enc_dtid)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalBER(ber.ChildGeneratedEncodeOptions(opts, "dialoguePortion")...)
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		encoder.Append(enc_dialogueportion)
	}
	if v.Components != nil {
		if v.berComponentsIndef_ && ber.BERGeneratedReplayEnabled(opts) {
			if len((v.Components).Values) < 1 {
				if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Continue"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
					return nil, constraintErr
				}
			}
			enc_components, err := tcapMarshalBERComponentPortion(v.Components, ber.ParentGeneratedCollectionSizeEncodeOptions(ber.ChildGeneratedEncodeOptions(opts, "components"))...)
			if err != nil {
				return nil, qualifyBERError(err, "components", "encoding", true)
			}
			if ber.BERGeneratedReplayEnabled(opts) && v.berComponentsIndef_ {
				indefTag_, _, indefContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_components)
				if tlvErr_ != nil {
					return nil, tlvErr_
				}
				{
					var encodeErr error
					enc_components, encodeErr = ber.EncodeConstructedIndefinite(indefTag_, indefContent_)
					if encodeErr != nil {
						return nil, qualifyBERError(encodeErr, "Components", "encoding", true)
					}
				}
			}
			encoder.Append(enc_components)
		} else {
			{
				if len((v.Components).Values) < 1 {
					if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Continue"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
						return nil, constraintErr
					}
				}
				_, err := appendBERLinearComponentPortion(encoder, v.Components, ber.ParentGeneratedCollectionSizeEncodeOptions(ber.ChildGeneratedEncodeOptions(opts, "components"))...)
				if err != nil {
					return nil, qualifyBERError(err, "components", "encoding", true)
				}
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes Continue to DER format.
func (v *Continue) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Continue receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := v.appendDERLinear(encoder)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *Continue) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Continue receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	if len(v.Otid) < 1 || len(v.Otid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(nil, "TCAPMessages.Continue"), "otid", "SIZE (1..4)", len(v.Otid)); constraintErr != nil {
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
	encoder.Append(enc_otid)
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(nil, "TCAPMessages.Continue"), "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
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
	encoder.Append(enc_dtid)
	if v.DialoguePortion != nil {
		enc_dialogueportion, extErr := v.DialoguePortion.MarshalDER()
		if extErr != nil {
			return nil, qualifyBERError(extErr, "dialoguePortion", "encoding", true)
		}
		encoder.Append(enc_dialogueportion)
	}
	if v.Components != nil {
		{
			if len((v.Components).Values) < 1 {
				if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(nil, "TCAPMessages.Continue"), "components", "SIZE (1..MAX)", len((v.Components).Values)); constraintErr != nil {
					return nil, constraintErr
				}
			}
			_, err := appendDERLinearComponentPortion(encoder, v.Components)
			if err != nil {
				return nil, qualifyBERError(err, "components", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes Continue from BER/DER format.
func (destination *Continue) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil Continue destination")
	}
	var next Continue
	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "Continue", "TCAPMessages", "Continue")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Continue
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "TCAPMessages.Continue", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Continue{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *Continue, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
	v.berComponentsIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassApplication && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "components", content[offset:])
				// Decode nested SEQUENCE_OF (ComponentPortion)
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
						v.berComponentsIndef_ = true
					}
				}
				dec_components, unmErr := tcapUnmarshalBERComponentPortion(tlv_components, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "components"))...)
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
	if ruleErr := v.checkTCAPDecodedRules(opts); ruleErr !=
		nil {
		return ruleErr
	}

	return nil
}

// MarshalBER encodes Abort to BER format.
func (v *Abort) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err

	}

	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "Abort", "TCAPMessages", "Abort")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: Abort receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *Abort) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	var children []byte
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Abort"), "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
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
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_reason)
		children = append(children, enc_reason...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *Abort) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(opts); err != nil {
		return nil, err

	}

	if v == nil {
		return nil, fmt.Errorf("%w: Abort receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(opts, "TCAPMessages.Abort"), "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
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
	encoder.Append(enc_dtid)
	if v.Reason != nil {
		{
			_, err := v.Reason.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "reason")...)
			if err != nil {
				return nil, qualifyBERError(err, "reason", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes Abort to DER format.
func (v *Abort) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Abort receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := v.appendDERLinear(encoder)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *Abort) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.checkTCAPEncodedRules(nil); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Abort receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassUniversal, Number: tag.TagSequence})
	if len(v.Dtid) < 1 || len(v.Dtid) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeSource(nil, "TCAPMessages.Abort"), "dtid", "SIZE (1..4)", len(v.Dtid)); constraintErr != nil {
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
	encoder.Append(enc_dtid)
	if v.Reason != nil {
		{
			_, err := v.Reason.appendDERLinear(encoder)
			if err != nil {
				return nil, qualifyBERError(err, "reason", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes Abort from BER/DER format.
func (destination *Abort) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil Abort destination")
	}
	var next Abort
	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "Abort", "TCAPMessages", "Abort")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Abort
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "TCAPMessages.Abort", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Abort{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *Abort, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
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
	if ruleErr := v.checkTCAPDecodedRules(opts); ruleErr !=
		nil {
		return ruleErr
	}

	return nil
}

// MarshalBERComponentPortion encodes a ComponentPortion list to BER.
func tcapMarshalBERComponentPortion(collection *ComponentPortion, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "ComponentPortion", "TCAPMessages", "ComponentPortion")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(collection.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) {
		return tcapMarshalBERComponentPortion(collection, []ber.EncodeOption{mode}...)
	}, collection)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(collection.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := appendBERLinearComponentPortion(encoder, collection, opts...)
			return appendErr
		})
	} else {
		encoded, err = marshalBERComponentPortion(collection, opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, collection.berReplayNode_, opts), nil
}
func marshalBERComponentPortion(collection *ComponentPortion, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeSource(opts, "TCAPMessages.marshalBERComponentPortion"), "ComponentPortion", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
		ber.RecordGeneratedBERChildPlacement(opts, len(children)-len(enc), enc)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 12, Constructed: true}, children)
}

func appendBERLinearComponentPortion(encoder *ber.LinearEncoder, collection *ComponentPortion, opts ...ber.EncodeOption) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(collection.berReplayNode_, opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeSource(opts, "TCAPMessages.appendBERLinearComponentPortion"), "ComponentPortion", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 12})
	for elemIndex := range list {
		elem := &list[elemIndex]
		_, err := elem.appendBERLinear(encoder, ber.ChildGeneratedElementEncodeOptions(opts, elemIndex)...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]", elemIndex), "encoding", true)
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDERComponentPortion encodes a ComponentPortion list to DER.
func tcapMarshalDERComponentPortion(collection *ComponentPortion) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := appendDERLinearComponentPortion(encoder, collection)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func appendDERLinearComponentPortion(encoder *ber.LinearEncoder, collection *ComponentPortion) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeSource(nil, "TCAPMessages.appendDERLinearComponentPortion"), "ComponentPortion", "SIZE (1..MAX)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 12})
	for elemIndex := range list {
		elem := &list[elemIndex]
		_, err := elem.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]", elemIndex), "encoding", true)
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBERComponentPortion decodes a ComponentPortion list from BER.
func tcapUnmarshalBERComponentPortion(data []byte, opts ...ber.DecodeOption) (returnValue *ComponentPortion, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "ComponentPortion", "TCAPMessages", "ComponentPortion")
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := tcapUnmarshalBERComponentPortion(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "TCAPMessages.ComponentPortion", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
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
	var result []Component
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem Component
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeIndexOptions(opts, len(result))...); unmErr != nil {
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
		decoded.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		if replayErr := ber.CompleteGeneratedBERDecode(opts, decoded, func(base *ComponentPortion, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return tcapMarshalBERComponentPortion(base, replayOpts...)
		}); replayErr != nil {
			return nil, replayErr
		}
	}
	return decoded, nil
}

// MarshalBER encodes Component to BER format.
func (v *Component) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "Component", "TCAPMessages", "Component")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: Component receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) && (v.Choice == ComponentChoiceBasicROS || v.Choice == ComponentChoiceReturnResultNotLast) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *Component) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Component receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	switch v.Choice {
	case ComponentChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice Component: basicROS is nil", ber.ErrInvalidValue)
		}
		_, err := v.BasicROS.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "basicROS")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		return nil, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice Component: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 7}, false)
		_, err := v.ReturnResultNotLast.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "returnResultNotLast")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, nil
	default:
		encoded, err := v.marshalBER(opts...)
		if err != nil {
			return nil, err
		}
		encoder.Append(encoded)
		return nil, nil
	}
}
func (v *Component) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
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
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Component receiver is nil", ber.ErrInvalidValue)
	}
	if v.Choice == ComponentChoiceBasicROS || v.Choice == ComponentChoiceReturnResultNotLast {
		encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendDERLinear(encoder)
			return appendErr
		})
		if err != nil {
			return nil, err
		}
		return encoded, nil
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

func (v *Component) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: Component receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ComponentChoiceBasicROS:
		if v.BasicROS == nil {
			return nil, fmt.Errorf("%w: choice Component: basicROS is nil", ber.ErrInvalidValue)
		}
		_, err := v.BasicROS.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "basicROS", "encoding", true)
		}
		return nil, nil
	case ComponentChoiceReturnResultNotLast:
		if v.ReturnResultNotLast == nil {
			return nil, fmt.Errorf("%w: choice Component: returnResultNotLast is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 7}, false)
		_, err := v.ReturnResultNotLast.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "returnResultNotLast", "encoding", true)
		}
		return nil, nil
	default:
		encoded, err := v.MarshalDER()
		if err != nil {
			return nil, err
		}
		encoder.Append(encoded)
		return nil, nil
	}
}

// UnmarshalBER decodes Component from BER/DER format.
func (destination *Component) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil Component destination")
	}
	var next Component
	v :=

		&next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "Component", "TCAPMessages", "Component")
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *Component, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Component
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "TCAPMessages.Component", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
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

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "Component.returnResultNotLast", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = ComponentChoiceReturnResultNotLast
		ber.MarkPreflightTarget(opts, "returnResultNotLast", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResultNotLast", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
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
		var dec ROS
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "basicROS")...); unmErr != nil {
			return qualifyBERError(unmErr, "basicROS", "decoding", false)
		}
		v.BasicROS = &dec
	}
	return nil
}

// MarshalBER encodes TCInvokeIdSet to BER format.
func (v *TCInvokeIdSet) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "TCInvokeIdSet", "TCAPMessages", "TCInvokeIdSet")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: TCInvokeIdSet receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *TCInvokeIdSet) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *TCInvokeIdSet) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if v.Choice == TCInvokeIdSetChoicePresent {
		if v.Present == nil {
			return nil, fmt.Errorf("encoding TCInvokeIdSet violates WITH COMPONENTS: Present must carry a constrained value")
		}
	}
	if v.Choice == TCInvokeIdSetChoiceAbsent {
		if constraintErr := ber.CheckEncodedValue(ber.EncodeSource(opts, "TCAPMessages.TCInvokeIdSet"), "absent", "Q.773 §4.2.2.2: component-id-present", "NULL"); constraintErr != nil {
			return nil, constraintErr
		}
	}
	switch v.Choice {
	case TCInvokeIdSetChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice TCInvokeIdSet: present is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Present)
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "present", "encoding", false)
		}
		if !(v.Present.Cmp(runtime.MustParseBigIntDecimal("-128")) >= 0 && v.Present.Cmp(runtime.MustParseBigIntDecimal("127")) <= 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeSource(opts, "TCAPMessages.TCInvokeIdSet"), "present", "Q.773 §4.2.2.2: component-id-one-octet", ber.ObserveInteger(v.Present)); constraintErr != nil {
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
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: TCInvokeIdSet receiver is nil", ber.ErrInvalidValue)
	}
	if v.Choice == TCInvokeIdSetChoicePresent {
		if v.Present == nil {
			return nil, fmt.Errorf("encoding TCInvokeIdSet violates WITH COMPONENTS: Present must carry a constrained value")
		}
	}
	if v.Choice == TCInvokeIdSetChoiceAbsent {
		if constraintErr := ber.CheckEncodedValue(ber.EncodeSource(nil, "TCAPMessages.TCInvokeIdSet"), "absent", "Q.773 §4.2.2.2: component-id-present", "NULL"); constraintErr != nil {
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

func (v *TCInvokeIdSet) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes TCInvokeIdSet from BER/DER format.
func (destination *TCInvokeIdSet) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil TCInvokeIdSet destination")
	}
	var next TCInvokeIdSet

	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "TCInvokeIdSet", "TCAPMessages", "TCInvokeIdSet")
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *TCInvokeIdSet, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TCInvokeIdSet
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "TCAPMessages.TCInvokeIdSet", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
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

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "TCInvokeIdSet.present", "decoding", false)
	}
	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "TCInvokeIdSet.absent", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = TCInvokeIdSetChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		decVal, _, intErr := ber.DecodeBigInt(choiceData, opts...)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
		if !(v.Present.Cmp(runtime.MustParseBigIntDecimal("-128")) >= 0 && v.Present.Cmp(runtime.MustParseBigIntDecimal("127")) <= 0) {
			if constraintErr := ber.CheckDecodedValue(opts, "present", "Q.773 §4.2.2.2: component-id-one-octet", ber.ObserveInteger(v.Present)); constraintErr != nil {
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
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for TCInvokeIdSet CHOICE", peekTag)
	}
	if v.Choice == TCInvokeIdSetChoicePresent {
		if v.Present == nil {
			return fmt.Errorf("decoded TCInvokeIdSet violates WITH COMPONENTS: Present must carry a constrained value")
		}
	}
	if v.Choice == TCInvokeIdSetChoiceAbsent {
		if constraintErr := ber.CheckDecodedValue(opts, "absent", "Q.773 §4.2.2.2: component-id-present", "NULL"); constraintErr != nil {
			return constraintErr
		}
	}
	return nil
}

// MarshalBER encodes AbortReason to BER format.
func (v *AbortReason) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	var finishTCAPProfile func([]byte, error) error
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "AbortReason", "TCAPMessages", "Abort-reason")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: AbortReason receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *AbortReason) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *AbortReason) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case AbortReasonChoicePAbortCause:
		if v.PAbortCause == nil {
			return nil, fmt.Errorf("%w: choice AbortReason: p-abortCause is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.PAbortCause.BigInt())
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "p-abortCause", "encoding", false)
		}
		if !(v.PAbortCause.BigInt().Cmp(runtime.MustParseBigIntDecimal("0")) >= 0 && v.PAbortCause.BigInt().Cmp(runtime.MustParseBigIntDecimal("127")) <= 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeSource(opts, "TCAPMessages.Abort-reason"), "p-abortCause", "(0..127)", ber.ObserveInteger(v.PAbortCause.BigInt())); constraintErr != nil {
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
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

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

func (v *AbortReason) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes AbortReason from BER/DER format.
func (destination *AbortReason) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil AbortReason destination")
	}
	var next AbortReason

	v := &next
	defer func() {
		if returnErr == nil {
			*destination =
				*v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "AbortReason", "TCAPMessages", "Abort-reason")
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *AbortReason, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AbortReason
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "TCAPMessages.Abort-reason", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
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

	if (peekTag.Class == tag.ClassApplication && peekTag.Number == 10) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "AbortReason.p-abortCause", "decoding", false)
	}
	if (peekTag.Class == tag.ClassApplication && peekTag.Number == 11) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "AbortReason.u-abortCause", "decoding", false)
	}
	if peekTag.Class == tag.ClassApplication && peekTag.Number == 10 && peekTag.Constructed == false {
		v.Choice = AbortReasonChoicePAbortCause
		ber.MarkPreflightTarget(opts, "p-abortCause", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "p-abortCause", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "p-abortCause", "decoding", false)
		}
		var named_pabortcause PAbortCause
		if namedErr := named_pabortcause.UnmarshalText([]byte(decVal.String())); namedErr != nil {
			return qualifyBERError(namedErr, "p-abortCause", "decoding", false)
		}
		v.PAbortCause = &named_pabortcause
		if !(v.PAbortCause.BigInt().Cmp(runtime.MustParseBigIntDecimal("0")) >= 0 && v.PAbortCause.BigInt().Cmp(runtime.MustParseBigIntDecimal("127")) <= 0) {
			if constraintErr := ber.CheckDecodedValue(opts, "p-abortCause", "(0..127)", ber.ObserveInteger(v.PAbortCause.BigInt())); constraintErr != nil {
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
func (v *AbortReason) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil AbortReason CHOICE")
	}
	count := 0
	if v.PAbortCause != nil {
		count++
	}
	if v.UAbortCause != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.PAbortCause == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.UAbortCause == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *Component) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil Component CHOICE")
	}
	count := 0
	if v.BasicROS != nil {
		count++
	}
	if v.ReturnResultNotLast != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.BasicROS == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.ReturnResultNotLast == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *TCInvokeIdSet) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil TCInvokeIdSet CHOICE")
	}
	count := 0
	if v.Present != nil {
		count++
	}
	if v.Absent != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.Present == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.Absent == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *TCMessage) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil TCMessage CHOICE")
	}
	count := 0
	if v.Unidirectional != nil {
		count++
	}
	if v.Begin != nil {
		count++
	}
	if v.End != nil {
		count++
	}
	if v.Continue != nil {
		count++
	}
	if v.Abort != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.Unidirectional == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.Begin == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 3:
		if v.End == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 4:
		if v.Continue == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 5:
		if v.Abort == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *Abort) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(&v.Dtid); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Reason); err != nil {
		return err
	}
	return nil
}
func (v *Abort) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(&v.Dtid) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Reason) {
		return true
	}
	return false
}
func (v Abort) equalTCAPValue(other any) bool {
	right, ok := other.(Abort)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Dtid, right.Dtid) {
		return false
	}
	if (v.Reason == nil) != (right.Reason == nil) {
		return false
	}
	if v.Reason != nil && !equalTCAPValue(*v.Reason, *right.Reason) {
		return false
	}
	return true
}
func (v *AbortReason) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.PAbortCause); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.UAbortCause); err != nil {
		return err
	}
	return nil
}
func (v *AbortReason) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.PAbortCause) {
		return true
	}
	if hasTCAPPresenceEditValue(v.UAbortCause) {
		return true
	}
	return false
}
func (v AbortReason) equalTCAPValue(other any) bool {
	right, ok := other.(AbortReason)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.PAbortCause == nil) != (right.PAbortCause == nil) {
		return false
	}
	if v.PAbortCause != nil && !equalTCAPValue(*v.PAbortCause, *right.PAbortCause) {
		return false
	}
	if (v.UAbortCause == nil) != (right.UAbortCause == nil) {
		return false
	}
	if v.UAbortCause != nil && !equalTCAPValue(*v.UAbortCause, *right.UAbortCause) {
		return false
	}
	return true
}
func (v *Begin) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(&v.Otid); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.DialoguePortion); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Components); err != nil {
		return err
	}
	return nil
}
func (v *Begin) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(&v.Otid) {
		return true
	}
	if hasTCAPPresenceEditValue(v.DialoguePortion) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Components) {
		return true
	}
	return false
}
func (v Begin) equalTCAPValue(other any) bool {
	right, ok := other.(Begin)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Otid, right.Otid) {
		return false
	}
	if (v.DialoguePortion == nil) != (right.DialoguePortion == nil) {
		return false
	}
	if v.DialoguePortion != nil && !equalTCAPValue(*v.DialoguePortion, *right.DialoguePortion) {
		return false
	}
	if (v.Components == nil) != (right.Components == nil) {
		return false
	}
	if v.Components != nil && !equalTCAPValue(*v.Components, *right.Components) {
		return false
	}
	return true
}
func (v *Component) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.BasicROS); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.ReturnResultNotLast); err != nil {
		return err
	}
	return nil
}
func (v *Component) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.BasicROS) {
		return true
	}
	if hasTCAPPresenceEditValue(v.ReturnResultNotLast) {
		return true
	}
	return false
}
func (v Component) equalTCAPValue(other any) bool {
	right, ok := other.(Component)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.BasicROS == nil) != (right.BasicROS == nil) {
		return false
	}
	if v.BasicROS != nil && !equalTCAPValue(*v.BasicROS, *right.BasicROS) {
		return false
	}
	if (v.ReturnResultNotLast == nil) != (right.ReturnResultNotLast == nil) {
		return false
	}
	if v.ReturnResultNotLast != nil && !equalTCAPValue(*v.ReturnResultNotLast, *right.ReturnResultNotLast) {
		return false
	}
	return true
}
func (v *ComponentPortion) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	for i := range v.Values {
		if err := validateTCAPStructureValue(&v.Values[i]); err != nil {
			return err
		}
	}
	return nil
}
func (v *ComponentPortion) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	for i := range v.Values {
		if hasTCAPPresenceEditValue(&v.Values[i]) {
			return true
		}
	}
	return false
}
func (v ComponentPortion) equalTCAPValue(other any) bool {
	right, ok := other.(ComponentPortion)
	if !ok {
		return false
	}
	_ = right
	if len(v.Values) != len(right.Values) {
		return false
	}
	for i := range v.Values {
		if !equalTCAPValue(v.Values[i], right.Values[i]) {
			return false
		}
	}
	return true
}
func (v *Continue) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(&v.Otid); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(&v.Dtid); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.DialoguePortion); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Components); err != nil {
		return err
	}
	return nil
}
func (v *Continue) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(&v.Otid) {
		return true
	}
	if hasTCAPPresenceEditValue(&v.Dtid) {
		return true
	}
	if hasTCAPPresenceEditValue(v.DialoguePortion) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Components) {
		return true
	}
	return false
}
func (v Continue) equalTCAPValue(other any) bool {
	right, ok := other.(Continue)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Otid, right.Otid) {
		return false
	}
	if !equalTCAPValue(v.Dtid, right.Dtid) {
		return false
	}
	if (v.DialoguePortion == nil) != (right.DialoguePortion == nil) {
		return false
	}
	if v.DialoguePortion != nil && !equalTCAPValue(*v.DialoguePortion, *right.DialoguePortion) {
		return false
	}
	if (v.Components == nil) != (right.Components == nil) {
		return false
	}
	if v.Components != nil && !equalTCAPValue(*v.Components, *right.Components) {
		return false
	}
	return true
}
func (v *End) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(&v.Dtid); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.DialoguePortion); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Components); err != nil {
		return err
	}
	return nil
}
func (v *End) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(&v.Dtid) {
		return true
	}
	if hasTCAPPresenceEditValue(v.DialoguePortion) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Components) {
		return true
	}
	return false
}
func (v End) equalTCAPValue(other any) bool {
	right, ok := other.(End)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Dtid, right.Dtid) {
		return false
	}
	if (v.DialoguePortion == nil) != (right.DialoguePortion == nil) {
		return false
	}
	if v.DialoguePortion != nil && !equalTCAPValue(*v.DialoguePortion, *right.DialoguePortion) {
		return false
	}
	if (v.Components == nil) != (right.Components == nil) {
		return false
	}
	if v.Components != nil && !equalTCAPValue(*v.Components, *right.Components) {
		return false
	}
	return true
}
func (v *PAbortCause) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	return nil
}
func (v *PAbortCause) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v PAbortCause) equalTCAPValue(other any) bool {
	right, ok := other.(PAbortCause)
	if !ok {
		return false
	}
	_ = right
	return v.BigInt().Cmp(right.BigInt()) == 0
}
func (v *TCInvokeIdSet) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	return nil
}
func (v *TCInvokeIdSet) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	return false
}
func (v TCInvokeIdSet) equalTCAPValue(other any) bool {
	right, ok := other.(TCInvokeIdSet)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.Present == nil) != (right.Present == nil) {
		return false
	}
	if v.Present != nil && !equalTCAPValue(*v.Present, *right.Present) {
		return false
	}
	if (v.Absent == nil) != (right.Absent == nil) {
		return false
	}
	if v.Absent != nil && !equalTCAPValue(*v.Absent, *right.Absent) {
		return false
	}
	return true
}
func (v *TCMessage) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Unidirectional); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Begin); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.End); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Continue); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Abort); err != nil {
		return err
	}
	return nil
}
func (v *TCMessage) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.Unidirectional) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Begin) {
		return true
	}
	if hasTCAPPresenceEditValue(v.End) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Continue) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Abort) {
		return true
	}
	return false
}
func (v TCMessage) equalTCAPValue(other any) bool {
	right, ok := other.(TCMessage)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.Unidirectional == nil) != (right.Unidirectional == nil) {
		return false
	}
	if v.Unidirectional != nil && !equalTCAPValue(*v.Unidirectional, *right.Unidirectional) {
		return false
	}
	if (v.Begin == nil) != (right.Begin == nil) {
		return false
	}
	if v.Begin != nil && !equalTCAPValue(*v.Begin, *right.Begin) {
		return false
	}
	if (v.End == nil) != (right.End == nil) {
		return false
	}
	if v.End != nil && !equalTCAPValue(*v.End, *right.End) {
		return false
	}
	if (v.Continue == nil) != (right.Continue == nil) {
		return false
	}
	if v.Continue != nil && !equalTCAPValue(*v.Continue, *right.Continue) {
		return false
	}
	if (v.Abort == nil) != (right.Abort == nil) {
		return false
	}
	if v.Abort != nil && !equalTCAPValue(*v.Abort, *right.Abort) {
		return false
	}
	return true
}
func (v *Unidirectional) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := validateTCAPStructureValue(v.DialoguePortion); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(&v.Components); err != nil {
		return err
	}
	return nil
}
func (v *Unidirectional) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.DialoguePortion) {
		return true
	}
	if hasTCAPPresenceEditValue(&v.Components) {
		return true
	}
	return false
}
func (v Unidirectional) equalTCAPValue(other any) bool {
	right, ok := other.(Unidirectional)
	if !ok {
		return false
	}
	_ = right
	if (v.DialoguePortion == nil) != (right.DialoguePortion == nil) {
		return false
	}
	if v.DialoguePortion != nil && !equalTCAPValue(*v.DialoguePortion, *right.DialoguePortion) {
		return false
	}
	if !equalTCAPValue(v.Components, right.Components) {
		return false
	}
	return true
}
