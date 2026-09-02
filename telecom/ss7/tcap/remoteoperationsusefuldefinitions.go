// Code generated from ASN.1 module "Remote-Operations-Useful-Definitions". DO NOT EDIT.

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

// ROSSingleAS choice constants.
const (
	ROSSingleASChoiceInvoke       = 1
	ROSSingleASChoiceReturnResult = 2
	ROSSingleASChoiceReturnError  = 3
	ROSSingleASChoiceReject       = 4
)

// ROSSingleAS represents the ASN.1 CHOICE type ROS-SingleAS.
type ROSSingleAS struct {
	Choice       int
	Invoke       *Invoke       `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError  `json:"ReturnError,omitempty"`
	Reject       *Reject       `json:"Reject,omitempty"`
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
	Choice       int
	Invoke       *Invoke       `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError  `json:"ReturnError,omitempty"`
	Reject       *Reject       `json:"Reject,omitempty"`
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
	Choice       int
	Invoke       *Invoke       `json:"Invoke,omitempty"`
	ReturnResult *ReturnResult `json:"ReturnResult,omitempty"`
	ReturnError  *ReturnError  `json:"ReturnError,omitempty"`
	Reject       *Reject       `json:"Reject,omitempty"`
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
	Choice  int
	Present *big.Int  `json:"Present,omitempty"`
	Absent  *struct{} `json:"Absent,omitempty"`
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
	Opcode Code             `asn1:""`
	Result runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
}

// ROSConsumerASInvokeLinkedId choice constants.
const (
	ROSConsumerASInvokeLinkedIdChoicePresent = 1
	ROSConsumerASInvokeLinkedIdChoiceAbsent  = 2
)

// ROSConsumerASInvokeLinkedId represents the ASN.1 CHOICE type ROS-ConsumerAS-invoke-linkedId.
type ROSConsumerASInvokeLinkedId struct {
	Choice  int
	Present *big.Int  `json:"Present,omitempty"`
	Absent  *struct{} `json:"Absent,omitempty"`
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
	Opcode Code             `asn1:""`
	Result runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
}

// ROSSupplierASInvokeLinkedId choice constants.
const (
	ROSSupplierASInvokeLinkedIdChoicePresent = 1
	ROSSupplierASInvokeLinkedIdChoiceAbsent  = 2
)

// ROSSupplierASInvokeLinkedId represents the ASN.1 CHOICE type ROS-SupplierAS-invoke-linkedId.
type ROSSupplierASInvokeLinkedId struct {
	Choice  int
	Present *big.Int  `json:"Present,omitempty"`
	Absent  *struct{} `json:"Absent,omitempty"`
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
	Opcode Code             `asn1:""`
	Result runtime.RawValue `asn1:"" asn1c:"raw-preserve"`
}

// MarshalBER encodes ROSSingleAS to BER format.
func (v *ROSSingleAS) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ROSSingleASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: invoke is nil")
		}
		enc_0, err := v.Invoke.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		if v.Invoke.LinkedId != nil {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding invoke: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ROSSingleASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: returnResult is nil")
		}
		enc_1, err := v.ReturnResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case ROSSingleASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: returnError is nil")
		}
		enc_2, err := v.ReturnError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding returnError: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case ROSSingleASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: reject is nil")
		}
		enc_3, err := v.Reject.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding reject: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROSSingleAS", v.Choice)
	}
}

// MarshalDER encodes ROSSingleAS to DER format.
func (v *ROSSingleAS) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ROSSingleASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: invoke is nil")
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		if v.Invoke.LinkedId != nil {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding invoke: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDERElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding invoke as DER: %w", derErr)
		}
		return enc_der_0, nil
	case ROSSingleASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: returnResult is nil")
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding returnResult as DER: %w", derErr)
		}
		return enc_der_1, nil
	case ROSSingleASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: returnError is nil")
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, fmt.Errorf("encoding returnError: %w", tagErr_enc_der_2)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDERElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding returnError as DER: %w", derErr)
		}
		return enc_der_2, nil
	case ROSSingleASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: reject is nil")
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, fmt.Errorf("encoding reject: %w", tagErr_enc_der_3)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDERElement(enc_der_3); derErr != nil {
			return nil, fmt.Errorf("encoding reject as DER: %w", derErr)
		}
		return enc_der_3, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROSSingleAS as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROSSingleAS from BER/DER format.
func (v *ROSSingleAS) UnmarshalBER(data []byte) error {
	*v = ROSSingleAS{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSSingleAS CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSSingleAS: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ROSSingleAS CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSingleAS", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ROSSingleASChoiceInvoke
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding invoke: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Invoke
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding invoke: %w", unmErr)
		}
		v.Invoke = &dec
		if v.Invoke.LinkedId != nil {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ROSSingleASChoiceReturnResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResult: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnResult: %w", unmErr)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ROSSingleASChoiceReturnError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnError: %w", unmErr)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ROSSingleASChoiceReject
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding reject: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding reject: %w", unmErr)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ROSSingleAS CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ROSConsumerAS to BER format.
func (v *ROSConsumerAS) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ROSConsumerASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: invoke is nil")
		}
		enc_0, err := v.Invoke.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		if v.Invoke.LinkedId != nil {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding invoke: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ROSConsumerASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: returnResult is nil")
		}
		enc_1, err := v.ReturnResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case ROSConsumerASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: returnError is nil")
		}
		enc_2, err := v.ReturnError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding returnError: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case ROSConsumerASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: reject is nil")
		}
		enc_3, err := v.Reject.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding reject: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROSConsumerAS", v.Choice)
	}
}

// MarshalDER encodes ROSConsumerAS to DER format.
func (v *ROSConsumerAS) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ROSConsumerASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: invoke is nil")
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		if v.Invoke.LinkedId != nil {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding invoke: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDERElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding invoke as DER: %w", derErr)
		}
		return enc_der_0, nil
	case ROSConsumerASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: returnResult is nil")
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding returnResult as DER: %w", derErr)
		}
		return enc_der_1, nil
	case ROSConsumerASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: returnError is nil")
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, fmt.Errorf("encoding returnError: %w", tagErr_enc_der_2)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDERElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding returnError as DER: %w", derErr)
		}
		return enc_der_2, nil
	case ROSConsumerASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: reject is nil")
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, fmt.Errorf("encoding reject: %w", tagErr_enc_der_3)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDERElement(enc_der_3); derErr != nil {
			return nil, fmt.Errorf("encoding reject as DER: %w", derErr)
		}
		return enc_der_3, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROSConsumerAS as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROSConsumerAS from BER/DER format.
func (v *ROSConsumerAS) UnmarshalBER(data []byte) error {
	*v = ROSConsumerAS{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSConsumerAS CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSConsumerAS: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ROSConsumerAS CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSConsumerAS", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ROSConsumerASChoiceInvoke
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding invoke: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Invoke
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding invoke: %w", unmErr)
		}
		v.Invoke = &dec
		if v.Invoke.LinkedId != nil {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ROSConsumerASChoiceReturnResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResult: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnResult: %w", unmErr)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ROSConsumerASChoiceReturnError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnError: %w", unmErr)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ROSConsumerASChoiceReject
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding reject: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding reject: %w", unmErr)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ROSConsumerAS CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ROSSupplierAS to BER format.
func (v *ROSSupplierAS) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ROSSupplierASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: invoke is nil")
		}
		enc_0, err := v.Invoke.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		if v.Invoke.LinkedId != nil {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding invoke: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ROSSupplierASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: returnResult is nil")
		}
		enc_1, err := v.ReturnResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case ROSSupplierASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: returnError is nil")
		}
		enc_2, err := v.ReturnError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding returnError: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case ROSSupplierASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: reject is nil")
		}
		enc_3, err := v.Reject.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding reject: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROSSupplierAS", v.Choice)
	}
}

// MarshalDER encodes ROSSupplierAS to DER format.
func (v *ROSSupplierAS) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ROSSupplierASChoiceInvoke:
		if v.Invoke == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: invoke is nil")
		}
		enc_der_0, err := v.Invoke.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding invoke: %w", err)
		}
		if v.Invoke.LinkedId != nil {
			return nil, fmt.Errorf("encoding Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding invoke: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDERElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding invoke as DER: %w", derErr)
		}
		return enc_der_0, nil
	case ROSSupplierASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: returnResult is nil")
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding returnResult as DER: %w", derErr)
		}
		return enc_der_1, nil
	case ROSSupplierASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: returnError is nil")
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, fmt.Errorf("encoding returnError: %w", tagErr_enc_der_2)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDERElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding returnError as DER: %w", derErr)
		}
		return enc_der_2, nil
	case ROSSupplierASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: reject is nil")
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, fmt.Errorf("encoding reject: %w", tagErr_enc_der_3)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDERElement(enc_der_3); derErr != nil {
			return nil, fmt.Errorf("encoding reject as DER: %w", derErr)
		}
		return enc_der_3, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROSSupplierAS as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROSSupplierAS from BER/DER format.
func (v *ROSSupplierAS) UnmarshalBER(data []byte) error {
	*v = ROSSupplierAS{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSSupplierAS CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSSupplierAS: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ROSSupplierAS CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSupplierAS", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ROSSupplierASChoiceInvoke
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding invoke: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Invoke
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding invoke: %w", unmErr)
		}
		v.Invoke = &dec
		if v.Invoke.LinkedId != nil {
			return fmt.Errorf("decoded Invoke violates WITH COMPONENTS: LinkedId must be absent")
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ROSSupplierASChoiceReturnResult
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnResult: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ReturnResult
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnResult: %w", unmErr)
		}
		v.ReturnResult = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ROSSupplierASChoiceReturnError
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding returnError: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ReturnError
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding returnError: %w", unmErr)
		}
		v.ReturnError = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ROSSupplierASChoiceReject
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding reject: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec Reject
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding reject: %w", unmErr)
		}
		v.Reject = &dec
	} else {
		return fmt.Errorf("unknown tag %s for ROSSupplierAS CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ROSSingleASInvokeLinkedId to BER format.
func (v *ROSSingleASInvokeLinkedId) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ROSSingleASInvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("choice ROSSingleASInvokeLinkedId: present is nil")
		}
		enc_0 := ber.EncodeBigInt(v.Present)
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding present: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ROSSingleASInvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding absent: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROSSingleASInvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes ROSSingleASInvokeLinkedId to DER format.
func (v *ROSSingleASInvokeLinkedId) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROSSingleASInvokeLinkedId as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROSSingleASInvokeLinkedId from BER/DER format.
func (v *ROSSingleASInvokeLinkedId) UnmarshalBER(data []byte) error {
	*v = ROSSingleASInvokeLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSSingleASInvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSSingleASInvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ROSSingleASInvokeLinkedId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSingleASInvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ROSSingleASInvokeLinkedIdChoicePresent
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
		v.Choice = ROSSingleASInvokeLinkedIdChoiceAbsent
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding absent: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding absent: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for ROSSingleASInvokeLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ROSSingleASReturnResultResult to BER format.
func (v *ROSSingleASReturnResultResult) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ROSSingleASReturnResultResult to DER format.
func (v *ROSSingleASReturnResultResult) MarshalDER() ([]byte, error) {
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	children = append(children, enc_result...)
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROSSingleASReturnResultResult as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROSSingleASReturnResultResult from BER/DER format.
func (v *ROSSingleASReturnResultResult) UnmarshalBER(data []byte) error {
	*v = ROSSingleASReturnResultResult{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ROSSingleASReturnResultResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSingleASReturnResultResult", Cause: ber.ErrExtraData}
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
		return &ber.DecodeError{Offset: offset, TypeName: "ROSSingleASReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ROSConsumerASInvokeLinkedId to BER format.
func (v *ROSConsumerASInvokeLinkedId) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ROSConsumerASInvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("choice ROSConsumerASInvokeLinkedId: present is nil")
		}
		enc_0 := ber.EncodeBigInt(v.Present)
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding present: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ROSConsumerASInvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding absent: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROSConsumerASInvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes ROSConsumerASInvokeLinkedId to DER format.
func (v *ROSConsumerASInvokeLinkedId) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROSConsumerASInvokeLinkedId as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROSConsumerASInvokeLinkedId from BER/DER format.
func (v *ROSConsumerASInvokeLinkedId) UnmarshalBER(data []byte) error {
	*v = ROSConsumerASInvokeLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSConsumerASInvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSConsumerASInvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ROSConsumerASInvokeLinkedId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSConsumerASInvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ROSConsumerASInvokeLinkedIdChoicePresent
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
		v.Choice = ROSConsumerASInvokeLinkedIdChoiceAbsent
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding absent: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding absent: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for ROSConsumerASInvokeLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ROSConsumerASReturnResultResult to BER format.
func (v *ROSConsumerASReturnResultResult) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ROSConsumerASReturnResultResult to DER format.
func (v *ROSConsumerASReturnResultResult) MarshalDER() ([]byte, error) {
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	children = append(children, enc_result...)
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROSConsumerASReturnResultResult as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROSConsumerASReturnResultResult from BER/DER format.
func (v *ROSConsumerASReturnResultResult) UnmarshalBER(data []byte) error {
	*v = ROSConsumerASReturnResultResult{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ROSConsumerASReturnResultResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSConsumerASReturnResultResult", Cause: ber.ErrExtraData}
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
		return &ber.DecodeError{Offset: offset, TypeName: "ROSConsumerASReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ROSSupplierASInvokeLinkedId to BER format.
func (v *ROSSupplierASInvokeLinkedId) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ROSSupplierASInvokeLinkedIdChoicePresent:
		if v.Present == nil {
			return nil, fmt.Errorf("choice ROSSupplierASInvokeLinkedId: present is nil")
		}
		enc_0 := ber.EncodeBigInt(v.Present)
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding present: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ROSSupplierASInvokeLinkedIdChoiceAbsent:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding absent: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ROSSupplierASInvokeLinkedId", v.Choice)
	}
}

// MarshalDER encodes ROSSupplierASInvokeLinkedId to DER format.
func (v *ROSSupplierASInvokeLinkedId) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROSSupplierASInvokeLinkedId as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROSSupplierASInvokeLinkedId from BER/DER format.
func (v *ROSSupplierASInvokeLinkedId) UnmarshalBER(data []byte) error {
	*v = ROSSupplierASInvokeLinkedId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ROSSupplierASInvokeLinkedId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ROSSupplierASInvokeLinkedId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ROSSupplierASInvokeLinkedId CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSupplierASInvokeLinkedId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = ROSSupplierASInvokeLinkedIdChoicePresent
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
		v.Choice = ROSSupplierASInvokeLinkedIdChoiceAbsent
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding absent: %w", tlvErr)
		}
		if len(rawVal) != 0 {
			return fmt.Errorf("decoding absent: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal))
		}
		v.Absent = &struct{}{}
	} else {
		return fmt.Errorf("unknown tag %s for ROSSupplierASInvokeLinkedId CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ROSSupplierASReturnResultResult to BER format.
func (v *ROSSupplierASReturnResultResult) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ROSSupplierASReturnResultResult to DER format.
func (v *ROSSupplierASReturnResultResult) MarshalDER() ([]byte, error) {
	var children []byte
	enc_opcode, err := v.Opcode.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding opcode: %w", err)
	}
	children = append(children, enc_opcode...)
	enc_result := v.Result.Bytes
	children = append(children, enc_result...)
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ROSSupplierASReturnResultResult as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ROSSupplierASReturnResultResult from BER/DER format.
func (v *ROSSupplierASReturnResultResult) UnmarshalBER(data []byte) error {
	*v = ROSSupplierASReturnResultResult{}
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ROSSupplierASReturnResultResult SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ROSSupplierASReturnResultResult", Cause: ber.ErrExtraData}
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
		return &ber.DecodeError{Offset: offset, TypeName: "ROSSupplierASReturnResultResult", Cause: ber.ErrExtraData}
	}
	return nil
}
