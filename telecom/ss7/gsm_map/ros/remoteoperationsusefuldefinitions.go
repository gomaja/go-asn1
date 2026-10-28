// Code generated from ASN.1 module "Remote-Operations-Useful-Definitions". DO NOT EDIT.

package ros

import (
	"fmt"
	"math/big"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
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

// ROSSingleASInvokeLinkedId choice constants.
const (
	ROSSingleASInvokeLinkedIdChoicePresent = 1
	ROSSingleASInvokeLinkedIdChoiceAbsent  = 2
)

// ROSSingleASInvokeLinkedId represents the ASN.1 CHOICE type ROS-SingleAS-invoke-linkedId.
type ROSSingleASInvokeLinkedId struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Present        *big.Int        `json:"Present,omitempty"`
	Absent         *struct{}       `json:"Absent,omitempty"`
}

// NewROSSingleASInvokeLinkedIdPresent creates a ROSSingleASInvokeLinkedId with the present alternative.
func NewROSSingleASInvokeLinkedIdPresent(v *big.Int) ROSSingleASInvokeLinkedId {
	return ROSSingleASInvokeLinkedId{
		Choice:  ROSSingleASInvokeLinkedIdChoicePresent,
		Present: v,
	}
}

// NewROSSingleASInvokeLinkedIdAbsent creates a ROSSingleASInvokeLinkedId with the absent alternative.
func NewROSSingleASInvokeLinkedIdAbsent(v struct{}) ROSSingleASInvokeLinkedId {
	return ROSSingleASInvokeLinkedId{
		Choice: ROSSingleASInvokeLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// ROSSingleASReturnResultResult represents the ASN.1 type ROS-SingleAS-returnResult-result (SEQUENCE).
type ROSSingleASReturnResultResult struct {
	Opcode Code `asn1:""`
	// Result carries one complete foreign encoding. WithoutBERReplay and DER
	// copy elements passing generic DER checks; foreign schema rules need a typed binding.
	Result         runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berReplayNode_ *ber.ReplayNode  `asn1:"-" json:"-"`
}

// ROSConsumerASInvokeLinkedId choice constants.
const (
	ROSConsumerASInvokeLinkedIdChoicePresent = 1
	ROSConsumerASInvokeLinkedIdChoiceAbsent  = 2
)

// ROSConsumerASInvokeLinkedId represents the ASN.1 CHOICE type ROS-ConsumerAS-invoke-linkedId.
type ROSConsumerASInvokeLinkedId struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Present        *big.Int        `json:"Present,omitempty"`
	Absent         *struct{}       `json:"Absent,omitempty"`
}

// NewROSConsumerASInvokeLinkedIdPresent creates a ROSConsumerASInvokeLinkedId with the present alternative.
func NewROSConsumerASInvokeLinkedIdPresent(v *big.Int) ROSConsumerASInvokeLinkedId {
	return ROSConsumerASInvokeLinkedId{
		Choice:  ROSConsumerASInvokeLinkedIdChoicePresent,
		Present: v,
	}
}

// NewROSConsumerASInvokeLinkedIdAbsent creates a ROSConsumerASInvokeLinkedId with the absent alternative.
func NewROSConsumerASInvokeLinkedIdAbsent(v struct{}) ROSConsumerASInvokeLinkedId {
	return ROSConsumerASInvokeLinkedId{
		Choice: ROSConsumerASInvokeLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// ROSConsumerASReturnResultResult represents the ASN.1 type ROS-ConsumerAS-returnResult-result (SEQUENCE).
type ROSConsumerASReturnResultResult struct {
	Opcode Code `asn1:""`
	// Result carries one complete foreign encoding. WithoutBERReplay and DER
	// copy elements passing generic DER checks; foreign schema rules need a typed binding.
	Result         runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berReplayNode_ *ber.ReplayNode  `asn1:"-" json:"-"`
}

// ROSSupplierASInvokeLinkedId choice constants.
const (
	ROSSupplierASInvokeLinkedIdChoicePresent = 1
	ROSSupplierASInvokeLinkedIdChoiceAbsent  = 2
)

// ROSSupplierASInvokeLinkedId represents the ASN.1 CHOICE type ROS-SupplierAS-invoke-linkedId.
type ROSSupplierASInvokeLinkedId struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Present        *big.Int        `json:"Present,omitempty"`
	Absent         *struct{}       `json:"Absent,omitempty"`
}

// NewROSSupplierASInvokeLinkedIdPresent creates a ROSSupplierASInvokeLinkedId with the present alternative.
func NewROSSupplierASInvokeLinkedIdPresent(v *big.Int) ROSSupplierASInvokeLinkedId {
	return ROSSupplierASInvokeLinkedId{
		Choice:  ROSSupplierASInvokeLinkedIdChoicePresent,
		Present: v,
	}
}

// NewROSSupplierASInvokeLinkedIdAbsent creates a ROSSupplierASInvokeLinkedId with the absent alternative.
func NewROSSupplierASInvokeLinkedIdAbsent(v struct{}) ROSSupplierASInvokeLinkedId {
	return ROSSupplierASInvokeLinkedId{
		Choice: ROSSupplierASInvokeLinkedIdChoiceAbsent,
		Absent: &v,
	}
}

// ROSSupplierASReturnResultResult represents the ASN.1 type ROS-SupplierAS-returnResult-result (SEQUENCE).
type ROSSupplierASReturnResultResult struct {
	Opcode Code `asn1:""`
	// Result carries one complete foreign encoding. WithoutBERReplay and DER
	// copy elements passing generic DER checks; foreign schema rules need a typed binding.
	Result         runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
	berReplayNode_ *ber.ReplayNode  `asn1:"-" json:"-"`
}

// MarshalBER encodes ROSSingleAS to BER format.
func (v *ROSSingleAS) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSingleAS receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROSSingleAS).MarshalBER, (*ROSSingleAS).marshalBER, 1)

}
func (v *ROSSingleAS) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *ROSSingleAS) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
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
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROSSingleAS) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROSSingleAS receiver is nil", ber.ErrInvalidValue)
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
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROSSingleAS from BER/DER format.
func (destination *ROSSingleAS) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROSSingleAS destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROSSingleAS)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Useful-Definitions.ROS-SingleAS", "child", (*ROSSingleAS).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROSSingleAS).MarshalBER)
		}

	}()

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
		return fmt.Errorf("%w: unknown tag %s for ROSSingleAS CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ROSConsumerAS to BER format.
func (v *ROSConsumerAS) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROSConsumerAS receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROSConsumerAS).MarshalBER, (*ROSConsumerAS).marshalBER, 1)

}
func (v *ROSConsumerAS) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *ROSConsumerAS) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
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
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROSConsumerAS) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROSConsumerAS receiver is nil", ber.ErrInvalidValue)
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
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROSConsumerAS from BER/DER format.
func (destination *ROSConsumerAS) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROSConsumerAS destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROSConsumerAS)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Useful-Definitions.ROS-ConsumerAS", "child", (*ROSConsumerAS).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROSConsumerAS).MarshalBER)
		}

	}()

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
		return fmt.Errorf("%w: unknown tag %s for ROSConsumerAS CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ROSSupplierAS to BER format.
func (v *ROSSupplierAS) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSupplierAS receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROSSupplierAS).MarshalBER, (*ROSSupplierAS).marshalBER, 1)

}
func (v *ROSSupplierAS) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *ROSSupplierAS) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
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
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROSSupplierAS) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROSSupplierAS receiver is nil", ber.ErrInvalidValue)
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
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROSSupplierAS from BER/DER format.
func (destination *ROSSupplierAS) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROSSupplierAS destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROSSupplierAS)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Useful-Definitions.ROS-SupplierAS", "child", (*ROSSupplierAS).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROSSupplierAS).MarshalBER)
		}

	}()

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
		return fmt.Errorf("%w: unknown tag %s for ROSSupplierAS CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ROSSingleASInvokeLinkedId to BER format.
func (v *ROSSingleASInvokeLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSingleASInvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROSSingleASInvokeLinkedId).MarshalBER, (*ROSSingleASInvokeLinkedId).marshalBER, 1)

}
func (v *ROSSingleASInvokeLinkedId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *ROSSingleASInvokeLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ROSSingleASInvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice ROSSingleASInvokeLinkedId: present is nil", ber.ErrInvalidValue)
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
	case ROSSingleASInvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROSSingleASInvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes ROSSingleASInvokeLinkedId to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROSSingleASInvokeLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROSSingleASInvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ROSSingleASInvokeLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case ROSSingleASInvokeLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ROSSingleASInvokeLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *ROSSingleASInvokeLinkedId) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROSSingleASInvokeLinkedId from BER/DER format.
func (destination *ROSSingleASInvokeLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROSSingleASInvokeLinkedId destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROSSingleASInvokeLinkedId)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Useful-Definitions.ROS-SingleAS-invoke-linkedId", "child", (*ROSSingleASInvokeLinkedId).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROSSingleASInvokeLinkedId).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROSSingleASInvokeLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSSingleASInvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSSingleASInvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ROSSingleASInvokeLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSingleASInvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSingleASInvokeLinkedId.present", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSingleASInvokeLinkedId.absent", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ROSSingleASInvokeLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = ROSSingleASInvokeLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		_ = rawVal
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("%w: unknown tag %s for ROSSingleASInvokeLinkedId CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ROSSingleASReturnResultResult to BER format.
func (v *ROSSingleASReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSingleASReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROSSingleASReturnResultResult).MarshalBER, (*ROSSingleASReturnResultResult).marshalBER, 1)

}
func (v *ROSSingleASReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_opcode)
	children = append(children, enc_opcode...)
	if rawErr := ber.ValidateRawValueIdentifier(v.Result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	enc_result := v.Result.Bytes
	if err := checkOpaqueElement(enc_result, opts, "result", -1, "Remote-Operations-Useful-Definitions.ROS-SingleAS-returnResult-result.result", nil); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ROSSingleASReturnResultResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ROSSingleASReturnResultResult to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROSSingleASReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROSSingleASReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if rawErr := ber.ValidateRawValueIdentifier(v.Result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, invalidDEROpaqueElement(enc_result, "result", "Remote-Operations-Useful-Definitions.ROS-SingleAS-returnResult-result.result")
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ROSSingleASReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ROSSingleASReturnResultResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROSSingleASReturnResultResult from BER/DER format.
func (destination *ROSSingleASReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROSSingleASReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROSSingleASReturnResultResult)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Useful-Definitions.ROS-SingleAS-returnResult-result", "child", (*ROSSingleASReturnResultResult).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROSSingleASReturnResultResult{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROSSingleASReturnResultResult).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ROSSingleASReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSingleASReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field opcode", ber.ErrUnexpectedElement)
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
		return fmt.Errorf("%w: missing required field result", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		rawTag_result, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Class: int(rawTag_result.Class), Tag: rawTag_result.Number, Constructed: rawTag_result.Constructed, Bytes: append([]byte(nil), content[offset:offset+n_result]...)}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ROSSingleASReturnResultResult", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ROSConsumerASInvokeLinkedId to BER format.
func (v *ROSConsumerASInvokeLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROSConsumerASInvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROSConsumerASInvokeLinkedId).MarshalBER, (*ROSConsumerASInvokeLinkedId).marshalBER, 1)

}
func (v *ROSConsumerASInvokeLinkedId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *ROSConsumerASInvokeLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ROSConsumerASInvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice ROSConsumerASInvokeLinkedId: present is nil", ber.ErrInvalidValue)
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
	case ROSConsumerASInvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROSConsumerASInvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes ROSConsumerASInvokeLinkedId to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROSConsumerASInvokeLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROSConsumerASInvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ROSConsumerASInvokeLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case ROSConsumerASInvokeLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ROSConsumerASInvokeLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *ROSConsumerASInvokeLinkedId) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROSConsumerASInvokeLinkedId from BER/DER format.
func (destination *ROSConsumerASInvokeLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROSConsumerASInvokeLinkedId destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROSConsumerASInvokeLinkedId)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Useful-Definitions.ROS-ConsumerAS-invoke-linkedId", "child", (*ROSConsumerASInvokeLinkedId).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROSConsumerASInvokeLinkedId).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROSConsumerASInvokeLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSConsumerASInvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSConsumerASInvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ROSConsumerASInvokeLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSConsumerASInvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSConsumerASInvokeLinkedId.present", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSConsumerASInvokeLinkedId.absent", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ROSConsumerASInvokeLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = ROSConsumerASInvokeLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		_ = rawVal
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("%w: unknown tag %s for ROSConsumerASInvokeLinkedId CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ROSConsumerASReturnResultResult to BER format.
func (v *ROSConsumerASReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROSConsumerASReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROSConsumerASReturnResultResult).MarshalBER, (*ROSConsumerASReturnResultResult).marshalBER, 1)

}
func (v *ROSConsumerASReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_opcode)
	children = append(children, enc_opcode...)
	if rawErr := ber.ValidateRawValueIdentifier(v.Result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	enc_result := v.Result.Bytes
	if err := checkOpaqueElement(enc_result, opts, "result", -1, "Remote-Operations-Useful-Definitions.ROS-ConsumerAS-returnResult-result.result", nil); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ROSConsumerASReturnResultResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ROSConsumerASReturnResultResult to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROSConsumerASReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROSConsumerASReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if rawErr := ber.ValidateRawValueIdentifier(v.Result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, invalidDEROpaqueElement(enc_result, "result", "Remote-Operations-Useful-Definitions.ROS-ConsumerAS-returnResult-result.result")
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ROSConsumerASReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ROSConsumerASReturnResultResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROSConsumerASReturnResultResult from BER/DER format.
func (destination *ROSConsumerASReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROSConsumerASReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROSConsumerASReturnResultResult)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Useful-Definitions.ROS-ConsumerAS-returnResult-result", "child", (*ROSConsumerASReturnResultResult).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROSConsumerASReturnResultResult{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROSConsumerASReturnResultResult).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ROSConsumerASReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSConsumerASReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field opcode", ber.ErrUnexpectedElement)
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
		return fmt.Errorf("%w: missing required field result", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		rawTag_result, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Class: int(rawTag_result.Class), Tag: rawTag_result.Number, Constructed: rawTag_result.Constructed, Bytes: append([]byte(nil), content[offset:offset+n_result]...)}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ROSConsumerASReturnResultResult", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ROSSupplierASInvokeLinkedId to BER format.
func (v *ROSSupplierASInvokeLinkedId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSupplierASInvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROSSupplierASInvokeLinkedId).MarshalBER, (*ROSSupplierASInvokeLinkedId).marshalBER, 1)

}
func (v *ROSSupplierASInvokeLinkedId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *ROSSupplierASInvokeLinkedId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ROSSupplierASInvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("%w: choice ROSSupplierASInvokeLinkedId: present is nil", ber.ErrInvalidValue)
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
	case ROSSupplierASInvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "absent", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROSSupplierASInvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes ROSSupplierASInvokeLinkedId to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROSSupplierASInvokeLinkedId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROSSupplierASInvokeLinkedId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case ROSSupplierASInvokeLinkedIdChoicePresent:
			return nil, qualifyBERError(err, "present", "encoding", true)
		case ROSSupplierASInvokeLinkedIdChoiceAbsent:
			return nil, qualifyBERError(err, "absent", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding ROSSupplierASInvokeLinkedId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *ROSSupplierASInvokeLinkedId) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROSSupplierASInvokeLinkedId from BER/DER format.
func (destination *ROSSupplierASInvokeLinkedId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROSSupplierASInvokeLinkedId destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROSSupplierASInvokeLinkedId)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Useful-Definitions.ROS-SupplierAS-invoke-linkedId", "child", (*ROSSupplierASInvokeLinkedId).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROSSupplierASInvokeLinkedId).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROSSupplierASInvokeLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSSupplierASInvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSSupplierASInvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding ROSSupplierASInvokeLinkedId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSupplierASInvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSupplierASInvokeLinkedId.present", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "ROSSupplierASInvokeLinkedId.absent", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ROSSupplierASInvokeLinkedIdChoicePresent
		ber.MarkPreflightTarget(opts, "present", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "present", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeBigIntValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "present", "decoding", false)
		}
		v.Present = decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = ROSSupplierASInvokeLinkedIdChoiceAbsent
		ber.MarkPreflightTarget(opts, "absent", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "absent", "decoding", false)
		}
		_ = rawVal
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "absent", "decoding", false)
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("%w: unknown tag %s for ROSSupplierASInvokeLinkedId CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ROSSupplierASReturnResultResult to BER format.
func (v *ROSSupplierASReturnResultResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ROSSupplierASReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ROSSupplierASReturnResultResult).MarshalBER, (*ROSSupplierASReturnResultResult).marshalBER, 1)

}
func (v *ROSSupplierASReturnResultResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalBER(ber.ChildEncodeOptions(opts, "opcode")...)
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_opcode)
	children = append(children, enc_opcode...)
	if rawErr := ber.ValidateRawValueIdentifier(v.Result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", false)
	}
	enc_result := v.Result.Bytes
	if err := checkOpaqueElement(enc_result, opts, "result", -1, "Remote-Operations-Useful-Definitions.ROS-SupplierAS-returnResult-result.result", nil); err != nil {
		return nil, qualifyBERError(err, "result", "encoding", false)
	}
	children = append(children, enc_result...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ROSSupplierASReturnResultResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ROSSupplierASReturnResultResult to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ROSSupplierASReturnResultResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ROSSupplierASReturnResultResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "opcode", "encoding", true)
	}
	children = append(children, enc_opcode...)
	if rawErr := ber.ValidateRawValueIdentifier(v.Result); rawErr != nil {
		return nil, qualifyBERError(rawErr, "result", "encoding", true)
	}
	enc_result := v.Result.Bytes
	if rawErr := ber.ValidateDEREncodedElement(enc_result); rawErr != nil {
		return nil, invalidDEROpaqueElement(enc_result, "result", "Remote-Operations-Useful-Definitions.ROS-SupplierAS-returnResult-result.result")
	}
	children = append(children, enc_result...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ROSSupplierASReturnResultResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ROSSupplierASReturnResultResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ROSSupplierASReturnResultResult from BER/DER format.
func (destination *ROSSupplierASReturnResultResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ROSSupplierASReturnResultResult destination is nil", ber.ErrInvalidValue)
	}
	v := new(ROSSupplierASReturnResultResult)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "Remote-Operations-Useful-Definitions.ROS-SupplierAS-returnResult-result", "child", (*ROSSupplierASReturnResultResult).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ROSSupplierASReturnResultResult{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ROSSupplierASReturnResultResult).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ROSSupplierASReturnResultResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSupplierASReturnResultResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode opcode
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field opcode", ber.ErrUnexpectedElement)
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
		return fmt.Errorf("%w: missing required field result", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "result", content[offset:])
		rawTag_result, n_result, _, tlvErr_result := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_result != nil {
			return qualifyBERError(tlvErr_result, "result", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "result", content[offset:], n_result)
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.Result = runtime.RawValue{Class: int(rawTag_result.Class), Tag: rawTag_result.Number, Constructed: rawTag_result.Constructed, Bytes: append([]byte(nil), content[offset:offset+n_result]...)}
		if offset < 0 || offset >
			len(content) || n_result < 0 || n_result > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_result
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ROSSupplierASReturnResultResult", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}
