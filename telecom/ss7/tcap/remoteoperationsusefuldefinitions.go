// Code generated from ASN.1 module "Remote-Operations-Useful-Definitions". DO NOT EDIT.

package tcap

import (
	"fmt"

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

// ROSSingleAS choice constants.
const (
	ROSSingleASChoiceInvoke       = 1
	ROSSingleASChoiceReturnResult = 2
	ROSSingleASChoiceReturnError  = 3
	ROSSingleASChoiceReject       = 4
)

// ROSSingleAS represents the ASN.1 CHOICE type ROS-SingleAS.
type ROSSingleAS struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Invoke         *Invoke         `json:"Invoke,omitempty"`
	ReturnResult   *ReturnResult   `json:"ReturnResult,omitempty"`
	ReturnError    *ReturnError    `json:"ReturnError,omitempty"`
	Reject         *Reject         `json:"Reject,omitempty"`
}

// NewROSSingleASInvoke creates a ROSSingleAS with the invoke alternative.
func NewROSSingleASInvoke(v Invoke) ROSSingleAS {
	return ROSSingleAS{
		Choice: ROSSingleASChoiceInvoke,
		Invoke: &v,
	}
}

// NewROSSingleASReturnResult creates a ROSSingleAS with the returnResult alternative.
func NewROSSingleASReturnResult(v ReturnResult) ROSSingleAS {
	return ROSSingleAS{
		Choice:       ROSSingleASChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewROSSingleASReturnError creates a ROSSingleAS with the returnError alternative.
func NewROSSingleASReturnError(v ReturnError) ROSSingleAS {
	return ROSSingleAS{
		Choice:      ROSSingleASChoiceReturnError,
		ReturnError: &v,
	}
}

// NewROSSingleASReject creates a ROSSingleAS with the reject alternative.
func NewROSSingleASReject(v Reject) ROSSingleAS {
	return ROSSingleAS{
		Choice: ROSSingleASChoiceReject,
		Reject: &v,
	}
}

// ROSConsumerAS choice constants.
const (
	ROSConsumerASChoiceInvoke       = 1
	ROSConsumerASChoiceReturnResult = 2
	ROSConsumerASChoiceReturnError  = 3
	ROSConsumerASChoiceReject       = 4
)

// ROSConsumerAS represents the ASN.1 CHOICE type ROS-ConsumerAS.
type ROSConsumerAS struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Invoke         *Invoke         `json:"Invoke,omitempty"`
	ReturnResult   *ReturnResult   `json:"ReturnResult,omitempty"`
	ReturnError    *ReturnError    `json:"ReturnError,omitempty"`
	Reject         *Reject         `json:"Reject,omitempty"`
}

// NewROSConsumerASInvoke creates a ROSConsumerAS with the invoke alternative.
func NewROSConsumerASInvoke(v Invoke) ROSConsumerAS {
	return ROSConsumerAS{
		Choice: ROSConsumerASChoiceInvoke,
		Invoke: &v,
	}
}

// NewROSConsumerASReturnResult creates a ROSConsumerAS with the returnResult alternative.
func NewROSConsumerASReturnResult(v ReturnResult) ROSConsumerAS {
	return ROSConsumerAS{
		Choice:       ROSConsumerASChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewROSConsumerASReturnError creates a ROSConsumerAS with the returnError alternative.
func NewROSConsumerASReturnError(v ReturnError) ROSConsumerAS {
	return ROSConsumerAS{
		Choice:      ROSConsumerASChoiceReturnError,
		ReturnError: &v,
	}
}

// NewROSConsumerASReject creates a ROSConsumerAS with the reject alternative.
func NewROSConsumerASReject(v Reject) ROSConsumerAS {
	return ROSConsumerAS{
		Choice: ROSConsumerASChoiceReject,
		Reject: &v,
	}
}

// ROSSupplierAS choice constants.
const (
	ROSSupplierASChoiceInvoke       = 1
	ROSSupplierASChoiceReturnResult = 2
	ROSSupplierASChoiceReturnError  = 3
	ROSSupplierASChoiceReject       = 4
)

// ROSSupplierAS represents the ASN.1 CHOICE type ROS-SupplierAS.
type ROSSupplierAS struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Invoke         *Invoke         `json:"Invoke,omitempty"`
	ReturnResult   *ReturnResult   `json:"ReturnResult,omitempty"`
	ReturnError    *ReturnError    `json:"ReturnError,omitempty"`
	Reject         *Reject         `json:"Reject,omitempty"`
}

// NewROSSupplierASInvoke creates a ROSSupplierAS with the invoke alternative.
func NewROSSupplierASInvoke(v Invoke) ROSSupplierAS {
	return ROSSupplierAS{
		Choice: ROSSupplierASChoiceInvoke,
		Invoke: &v,
	}
}

// NewROSSupplierASReturnResult creates a ROSSupplierAS with the returnResult alternative.
func NewROSSupplierASReturnResult(v ReturnResult) ROSSupplierAS {
	return ROSSupplierAS{
		Choice:       ROSSupplierASChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewROSSupplierASReturnError creates a ROSSupplierAS with the returnError alternative.
func NewROSSupplierASReturnError(v ReturnError) ROSSupplierAS {
	return ROSSupplierAS{
		Choice:      ROSSupplierASChoiceReturnError,
		ReturnError: &v,
	}
}

// NewROSSupplierASReject creates a ROSSupplierAS with the reject alternative.
func NewROSSupplierASReject(v Reject) ROSSupplierAS {
	return ROSSupplierAS{
		Choice: ROSSupplierASChoiceReject,
		Reject: &v,
	}
}

// MarshalBER encodes ROSSingleAS to BER format.
func (v *ROSSingleAS) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
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
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "ROSSingleAS", "Remote-Operations-Useful-Definitions", "ROS-SingleAS")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: ROSSingleAS receiver is nil", ber.ErrInvalidValue)
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
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) && (v.Choice == ROSSingleASChoiceInvoke || v.Choice == ROSSingleASChoiceReturnResult || v.Choice == ROSSingleASChoiceReturnError || v.Choice == ROSSingleASChoiceReject) {
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
func (v *ROSSingleAS) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSingleAS receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	switch v.Choice {
	case ROSSingleASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: invoke is nil", ber.ErrInvalidValue)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, false)
		_, err := v.Invoke.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		return nil, nil
	case ROSSingleASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: returnResult is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, false)
		_, err := v.ReturnResult.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		return nil, nil
	case ROSSingleASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: returnError is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, false)
		_, err := v.ReturnError.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		return nil, nil
	case ROSSingleASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: reject is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, false)
		_, err := v.Reject.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
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
func (v *ROSSingleAS) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	switch v.Choice {
	case ROSSingleASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: invoke is nil", ber.ErrInvalidValue)
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
	case ROSSingleASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: returnResult is nil", ber.ErrInvalidValue)
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
	case ROSSingleASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: returnError is nil", ber.ErrInvalidValue)
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
	case ROSSingleASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: reject is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for ROSSingleAS", v.Choice)
	}
}

// MarshalDER encodes ROSSingleAS to DER format.
func (v *ROSSingleAS) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSingleAS receiver is nil", ber.ErrInvalidValue)
	}
	if v.Choice == ROSSingleASChoiceInvoke || v.Choice == ROSSingleASChoiceReturnResult || v.Choice == ROSSingleASChoiceReturnError || v.Choice == ROSSingleASChoiceReject {
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
	case ROSSingleASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: invoke is nil", ber.ErrInvalidValue)
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
	case ROSSingleASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: returnResult is nil", ber.ErrInvalidValue)
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
	case ROSSingleASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: returnError is nil", ber.ErrInvalidValue)
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
	case ROSSingleASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: reject is nil", ber.ErrInvalidValue)
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
		case ROSSingleASChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case ROSSingleASChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case ROSSingleASChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case ROSSingleASChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ROSSingleAS as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *ROSSingleAS) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSingleAS receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ROSSingleASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: invoke is nil", ber.ErrInvalidValue)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, false)
		_, err := v.Invoke.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		return nil, nil
	case ROSSingleASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: returnResult is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, false)
		_, err := v.ReturnResult.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		return nil, nil
	case ROSSingleASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: returnError is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, false)
		_, err := v.ReturnError.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		return nil, nil
	case ROSSingleASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleAS: reject is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, false)
		_, err := v.Reject.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
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

// UnmarshalBER decodes ROSSingleAS from BER/DER format.
func (destination *ROSSingleAS) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil ROSSingleAS destination")
	}
	var next ROSSingleAS

	v :=
		&next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "ROSSingleAS", "Remote-Operations-Useful-Definitions", "ROS-SingleAS")
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *ROSSingleAS, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ROSSingleAS
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Useful-Definitions.ROS-SingleAS", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROSSingleAS{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSSingleAS CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSSingleAS: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ROSSingleAS CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSingleAS", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSingleAS.invoke", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSingleAS.returnResult", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSingleAS.returnError", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSingleAS.reject", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ROSSingleASChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Invoke
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ROSSingleASChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ROSSingleASChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ROSSingleASChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ROSSingleAS CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ROSConsumerAS to BER format.
func (v *ROSConsumerAS) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
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
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "ROSConsumerAS", "Remote-Operations-Useful-Definitions", "ROS-ConsumerAS")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: ROSConsumerAS receiver is nil", ber.ErrInvalidValue)
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
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) && (v.Choice == ROSConsumerASChoiceInvoke || v.Choice == ROSConsumerASChoiceReturnResult || v.Choice == ROSConsumerASChoiceReturnError || v.Choice == ROSConsumerASChoiceReject) {
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
func (v *ROSConsumerAS) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROSConsumerAS receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	switch v.Choice {
	case ROSConsumerASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: invoke is nil", ber.ErrInvalidValue)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, false)
		_, err := v.Invoke.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		return nil, nil
	case ROSConsumerASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: returnResult is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, false)
		_, err := v.ReturnResult.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		return nil, nil
	case ROSConsumerASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: returnError is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, false)
		_, err := v.ReturnError.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		return nil, nil
	case ROSConsumerASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: reject is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, false)
		_, err := v.Reject.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
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
func (v *ROSConsumerAS) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	switch v.Choice {
	case ROSConsumerASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: invoke is nil", ber.ErrInvalidValue)
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
	case ROSConsumerASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: returnResult is nil", ber.ErrInvalidValue)
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
	case ROSConsumerASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: returnError is nil", ber.ErrInvalidValue)
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
	case ROSConsumerASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: reject is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for ROSConsumerAS", v.Choice)
	}
}

// MarshalDER encodes ROSConsumerAS to DER format.
func (v *ROSConsumerAS) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROSConsumerAS receiver is nil", ber.ErrInvalidValue)
	}
	if v.Choice == ROSConsumerASChoiceInvoke || v.Choice == ROSConsumerASChoiceReturnResult || v.Choice == ROSConsumerASChoiceReturnError || v.Choice == ROSConsumerASChoiceReject {
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
	case ROSConsumerASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: invoke is nil", ber.ErrInvalidValue)
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
	case ROSConsumerASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: returnResult is nil", ber.ErrInvalidValue)
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
	case ROSConsumerASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: returnError is nil", ber.ErrInvalidValue)
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
	case ROSConsumerASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: reject is nil", ber.ErrInvalidValue)
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
		case ROSConsumerASChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case ROSConsumerASChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case ROSConsumerASChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case ROSConsumerASChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ROSConsumerAS as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *ROSConsumerAS) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROSConsumerAS receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ROSConsumerASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: invoke is nil", ber.ErrInvalidValue)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, false)
		_, err := v.Invoke.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		return nil, nil
	case ROSConsumerASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: returnResult is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, false)
		_, err := v.ReturnResult.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		return nil, nil
	case ROSConsumerASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: returnError is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, false)
		_, err := v.ReturnError.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		return nil, nil
	case ROSConsumerASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerAS: reject is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, false)
		_, err := v.Reject.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
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

// UnmarshalBER decodes ROSConsumerAS from BER/DER format.
func (destination *ROSConsumerAS) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil ROSConsumerAS destination")
	}
	var next ROSConsumerAS

	v := &next

	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "ROSConsumerAS", "Remote-Operations-Useful-Definitions", "ROS-ConsumerAS")
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *ROSConsumerAS, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ROSConsumerAS
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Useful-Definitions.ROS-ConsumerAS", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROSConsumerAS{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSConsumerAS CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSConsumerAS: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ROSConsumerAS CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSConsumerAS", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSConsumerAS.invoke", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSConsumerAS.returnResult", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSConsumerAS.returnError", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSConsumerAS.reject", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ROSConsumerASChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Invoke
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ROSConsumerASChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ROSConsumerASChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ROSConsumerASChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ROSConsumerAS CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ROSSupplierAS to BER format.
func (v *ROSSupplierAS) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
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
	opts, finishTCAPProfile = ber.StageTCAPEncode(opts, "ROSSupplierAS", "Remote-Operations-Useful-Definitions", "ROS-SupplierAS")
	defer func() {
		returnErr = finishTCAPProfile(returnBytes, returnErr)
		if returnErr != nil {
			returnBytes = nil
		}
	}()
	if v == nil {
		return nil, fmt.Errorf("%w: ROSSupplierAS receiver is nil", ber.ErrInvalidValue)
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
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) && (v.Choice == ROSSupplierASChoiceInvoke || v.Choice == ROSSupplierASChoiceReturnResult || v.Choice == ROSSupplierASChoiceReturnError || v.Choice == ROSSupplierASChoiceReject) {
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
func (v *ROSSupplierAS) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSupplierAS receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	switch v.Choice {
	case ROSSupplierASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: invoke is nil", ber.ErrInvalidValue)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, false)
		_, err := v.Invoke.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "invoke")...)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		return nil, nil
	case ROSSupplierASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: returnResult is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, false)
		_, err := v.ReturnResult.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "returnResult")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		return nil, nil
	case ROSSupplierASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: returnError is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, false)
		_, err := v.ReturnError.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "returnError")...)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		return nil, nil
	case ROSSupplierASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: reject is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, false)
		_, err := v.Reject.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "reject")...)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
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
func (v *ROSSupplierAS) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	switch v.Choice {
	case ROSSupplierASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: invoke is nil", ber.ErrInvalidValue)
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
	case ROSSupplierASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: returnResult is nil", ber.ErrInvalidValue)
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
	case ROSSupplierASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: returnError is nil", ber.ErrInvalidValue)
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
	case ROSSupplierASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: reject is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for ROSSupplierAS", v.Choice)
	}
}

// MarshalDER encodes ROSSupplierAS to DER format.
func (v *ROSSupplierAS) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSupplierAS receiver is nil", ber.ErrInvalidValue)
	}
	if v.Choice == ROSSupplierASChoiceInvoke || v.Choice == ROSSupplierASChoiceReturnResult || v.Choice == ROSSupplierASChoiceReturnError || v.Choice == ROSSupplierASChoiceReject {
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
	case ROSSupplierASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: invoke is nil", ber.ErrInvalidValue)
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
	case ROSSupplierASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: returnResult is nil", ber.ErrInvalidValue)
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
	case ROSSupplierASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: returnError is nil", ber.ErrInvalidValue)
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
	case ROSSupplierASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: reject is nil", ber.ErrInvalidValue)
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
		case ROSSupplierASChoiceInvoke:
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		case ROSSupplierASChoiceReturnResult:
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		case ROSSupplierASChoiceReturnError:
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		case ROSSupplierASChoiceReject:
			return nil, qualifyBERError(err, "reject", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ROSSupplierAS as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *ROSSupplierAS) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSupplierAS receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ROSSupplierASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: invoke is nil", ber.ErrInvalidValue)
		}
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS union")
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, false)
		_, err := v.Invoke.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "invoke", "encoding", true)
		}
		return nil, nil
	case ROSSupplierASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: returnResult is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, false)
		_, err := v.ReturnResult.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "returnResult", "encoding", true)
		}
		return nil, nil
	case ROSSupplierASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: returnError is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, false)
		_, err := v.ReturnError.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "returnError", "encoding", true)
		}
		return nil, nil
	case ROSSupplierASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierAS: reject is nil", ber.ErrInvalidValue)
		}
		encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, false)
		_, err := v.Reject.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "reject", "encoding", true)
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

// UnmarshalBER decodes ROSSupplierAS from BER/DER format.
func (destination *ROSSupplierAS) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil ROSSupplierAS destination")
	}
	var next ROSSupplierAS

	v := &next

	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackTCAPForm(opts, "ROSSupplierAS", "Remote-Operations-Useful-Definitions", "ROS-SupplierAS")
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *ROSSupplierAS, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ROSSupplierAS
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Useful-Definitions.ROS-SupplierAS", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROSSupplierAS{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSSupplierAS CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSSupplierAS: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ROSSupplierAS CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSupplierAS", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSupplierAS.invoke", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSupplierAS.returnResult", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSupplierAS.returnError", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSupplierAS.reject", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ROSSupplierASChoiceInvoke
		ber.MarkPreflightTarget(opts, "invoke", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "invoke", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Invoke
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "invoke")...); unmErr != nil {
			return qualifyBERError(unmErr, "invoke", "decoding", false)
		}
		v.Invoke = &dec
		if !((v.Invoke.LinkedId == nil) || (v.Invoke.LinkedId != nil)) {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS union")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ROSSupplierASChoiceReturnResult
		ber.MarkPreflightTarget(opts, "returnResult", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnResult", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnResult")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnResult", "decoding", false)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ROSSupplierASChoiceReturnError
		ber.MarkPreflightTarget(opts, "returnError", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "returnError", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "returnError")...); unmErr != nil {
			return qualifyBERError(unmErr, "returnError", "decoding", false)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ROSSupplierASChoiceReject
		ber.MarkPreflightTarget(opts, "reject", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "reject", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "reject")...); unmErr != nil {
			return qualifyBERError(unmErr, "reject", "decoding", false)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ROSSupplierAS CHOICE", peekTag)
	}
	return nil
}
func (v *ROSConsumerAS) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil ROSConsumerAS CHOICE")
	}
	count := 0
	if v.Invoke != nil {
		count++
	}
	if v.ReturnResult != nil {
		count++
	}
	if v.ReturnError != nil {
		count++
	}
	if v.Reject != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.Invoke == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.ReturnResult == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 3:
		if v.ReturnError == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 4:
		if v.Reject == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *ROSSingleAS) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil ROSSingleAS CHOICE")
	}
	count := 0
	if v.Invoke != nil {
		count++
	}
	if v.ReturnResult != nil {
		count++
	}
	if v.ReturnError != nil {
		count++
	}
	if v.Reject != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.Invoke == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.ReturnResult == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 3:
		if v.ReturnError == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 4:
		if v.Reject == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *ROSSupplierAS) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil ROSSupplierAS CHOICE")
	}
	count := 0
	if v.Invoke != nil {
		count++
	}
	if v.ReturnResult != nil {
		count++
	}
	if v.ReturnError != nil {
		count++
	}
	if v.Reject != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.Invoke == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 2:
		if v.ReturnResult == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 3:
		if v.ReturnError == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	case 4:
		if v.Reject == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *ROSConsumerAS) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Invoke); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.ReturnResult); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.ReturnError); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Reject); err != nil {
		return err
	}
	return nil
}
func (v *ROSConsumerAS) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.Invoke) {
		return true
	}
	if hasTCAPPresenceEditValue(v.ReturnResult) {
		return true
	}
	if hasTCAPPresenceEditValue(v.ReturnError) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Reject) {
		return true
	}
	return false
}
func (v ROSConsumerAS) equalTCAPValue(other any) bool {
	right, ok := other.(ROSConsumerAS)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.Invoke == nil) != (right.Invoke == nil) {
		return false
	}
	if v.Invoke != nil && !equalTCAPValue(*v.Invoke, *right.Invoke) {
		return false
	}
	if (v.ReturnResult == nil) != (right.ReturnResult == nil) {
		return false
	}
	if v.ReturnResult != nil && !equalTCAPValue(*v.ReturnResult, *right.ReturnResult) {
		return false
	}
	if (v.ReturnError == nil) != (right.ReturnError == nil) {
		return false
	}
	if v.ReturnError != nil && !equalTCAPValue(*v.ReturnError, *right.ReturnError) {
		return false
	}
	if (v.Reject == nil) != (right.Reject == nil) {
		return false
	}
	if v.Reject != nil && !equalTCAPValue(*v.Reject, *right.Reject) {
		return false
	}
	return true
}
func (v *ROSSingleAS) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Invoke); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.ReturnResult); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.ReturnError); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Reject); err != nil {
		return err
	}
	return nil
}
func (v *ROSSingleAS) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.Invoke) {
		return true
	}
	if hasTCAPPresenceEditValue(v.ReturnResult) {
		return true
	}
	if hasTCAPPresenceEditValue(v.ReturnError) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Reject) {
		return true
	}
	return false
}
func (v ROSSingleAS) equalTCAPValue(other any) bool {
	right, ok := other.(ROSSingleAS)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.Invoke == nil) != (right.Invoke == nil) {
		return false
	}
	if v.Invoke != nil && !equalTCAPValue(*v.Invoke, *right.Invoke) {
		return false
	}
	if (v.ReturnResult == nil) != (right.ReturnResult == nil) {
		return false
	}
	if v.ReturnResult != nil && !equalTCAPValue(*v.ReturnResult, *right.ReturnResult) {
		return false
	}
	if (v.ReturnError == nil) != (right.ReturnError == nil) {
		return false
	}
	if v.ReturnError != nil && !equalTCAPValue(*v.ReturnError, *right.ReturnError) {
		return false
	}
	if (v.Reject == nil) != (right.Reject == nil) {
		return false
	}
	if v.Reject != nil && !equalTCAPValue(*v.Reject, *right.Reject) {
		return false
	}
	return true
}
func (v *ROSSupplierAS) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Invoke); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.ReturnResult); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.ReturnError); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.Reject); err != nil {
		return err
	}
	return nil
}
func (v *ROSSupplierAS) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.Invoke) {
		return true
	}
	if hasTCAPPresenceEditValue(v.ReturnResult) {
		return true
	}
	if hasTCAPPresenceEditValue(v.ReturnError) {
		return true
	}
	if hasTCAPPresenceEditValue(v.Reject) {
		return true
	}
	return false
}
func (v ROSSupplierAS) equalTCAPValue(other any) bool {
	right, ok := other.(ROSSupplierAS)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.Invoke == nil) != (right.Invoke == nil) {
		return false
	}
	if v.Invoke != nil && !equalTCAPValue(*v.Invoke, *right.Invoke) {
		return false
	}
	if (v.ReturnResult == nil) != (right.ReturnResult == nil) {
		return false
	}
	if v.ReturnResult != nil && !equalTCAPValue(*v.ReturnResult, *right.ReturnResult) {
		return false
	}
	if (v.ReturnError == nil) != (right.ReturnError == nil) {
		return false
	}
	if v.ReturnError != nil && !equalTCAPValue(*v.ReturnError, *right.ReturnError) {
		return false
	}
	if (v.Reject == nil) != (right.Reject == nil) {
		return false
	}
	if v.Reject != nil && !equalTCAPValue(*v.Reject, *right.Reject) {
		return false
	}
	return true
}
