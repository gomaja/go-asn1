// Code generated from ASN.1 module "Remote-Operations-Useful-Definitions". DO NOT EDIT.

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

// NewROSSingleASInvoke creates a ROS-SingleAS with the invoke alternative.
func NewROSSingleASInvoke(v Invoke) ROSSingleAS {
	return ROSSingleAS{
		Choice: ROSSingleASChoiceInvoke,
		Invoke: &v,
	}
}

// NewROSSingleASReturnResult creates a ROS-SingleAS with the returnResult alternative.
func NewROSSingleASReturnResult(v ReturnResult) ROSSingleAS {
	return ROSSingleAS{
		Choice:       ROSSingleASChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewROSSingleASReturnError creates a ROS-SingleAS with the returnError alternative.
func NewROSSingleASReturnError(v ReturnError) ROSSingleAS {
	return ROSSingleAS{
		Choice:      ROSSingleASChoiceReturnError,
		ReturnError: &v,
	}
}

// NewROSSingleASReject creates a ROS-SingleAS with the reject alternative.
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

// NewROSConsumerASInvoke creates a ROS-ConsumerAS with the invoke alternative.
func NewROSConsumerASInvoke(v Invoke) ROSConsumerAS {
	return ROSConsumerAS{
		Choice: ROSConsumerASChoiceInvoke,
		Invoke: &v,
	}
}

// NewROSConsumerASReturnResult creates a ROS-ConsumerAS with the returnResult alternative.
func NewROSConsumerASReturnResult(v ReturnResult) ROSConsumerAS {
	return ROSConsumerAS{
		Choice:       ROSConsumerASChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewROSConsumerASReturnError creates a ROS-ConsumerAS with the returnError alternative.
func NewROSConsumerASReturnError(v ReturnError) ROSConsumerAS {
	return ROSConsumerAS{
		Choice:      ROSConsumerASChoiceReturnError,
		ReturnError: &v,
	}
}

// NewROSConsumerASReject creates a ROS-ConsumerAS with the reject alternative.
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

// NewROSSupplierASInvoke creates a ROS-SupplierAS with the invoke alternative.
func NewROSSupplierASInvoke(v Invoke) ROSSupplierAS {
	return ROSSupplierAS{
		Choice: ROSSupplierASChoiceInvoke,
		Invoke: &v,
	}
}

// NewROSSupplierASReturnResult creates a ROS-SupplierAS with the returnResult alternative.
func NewROSSupplierASReturnResult(v ReturnResult) ROSSupplierAS {
	return ROSSupplierAS{
		Choice:       ROSSupplierASChoiceReturnResult,
		ReturnResult: &v,
	}
}

// NewROSSupplierASReturnError creates a ROS-SupplierAS with the returnError alternative.
func NewROSSupplierASReturnError(v ReturnError) ROSSupplierAS {
	return ROSSupplierAS{
		Choice:      ROSSupplierASChoiceReturnError,
		ReturnError: &v,
	}
}

// NewROSSupplierASReject creates a ROS-SupplierAS with the reject alternative.
func NewROSSupplierASReject(v Reject) ROSSupplierAS {
	return ROSSupplierAS{
		Choice: ROSSupplierASChoiceReject,
		Reject: &v,
	}
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
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_0)
		return enc_0, nil
	case ROSSingleASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: returnResult is nil")
		}
		enc_1, err := v.ReturnResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_1)
		return enc_1, nil
	case ROSSingleASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: returnError is nil")
		}
		enc_2, err := v.ReturnError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	case ROSSingleASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: reject is nil")
		}
		enc_3, err := v.Reject.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_3)
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
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_0)
		return enc_der_0, nil
	case ROSSingleASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: returnResult is nil")
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_der_1)
		return enc_der_1, nil
	case ROSSingleASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: returnError is nil")
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_der_2)
		return enc_der_2, nil
	case ROSSingleASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSSingleAS: reject is nil")
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_der_3)
		return enc_der_3, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes ROSSingleAS from BER/DER format.
func (v *ROSSingleAS) UnmarshalBER(data []byte) error {
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

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
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
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_0)
		return enc_0, nil
	case ROSConsumerASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: returnResult is nil")
		}
		enc_1, err := v.ReturnResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_1)
		return enc_1, nil
	case ROSConsumerASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: returnError is nil")
		}
		enc_2, err := v.ReturnError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	case ROSConsumerASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: reject is nil")
		}
		enc_3, err := v.Reject.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_3)
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
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_0)
		return enc_der_0, nil
	case ROSConsumerASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: returnResult is nil")
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_der_1)
		return enc_der_1, nil
	case ROSConsumerASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: returnError is nil")
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_der_2)
		return enc_der_2, nil
	case ROSConsumerASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSConsumerAS: reject is nil")
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_der_3)
		return enc_der_3, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes ROSConsumerAS from BER/DER format.
func (v *ROSConsumerAS) UnmarshalBER(data []byte) error {
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

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
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
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_0)
		return enc_0, nil
	case ROSSupplierASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: returnResult is nil")
		}
		enc_1, err := v.ReturnResult.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_1)
		return enc_1, nil
	case ROSSupplierASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: returnError is nil")
		}
		enc_2, err := v.ReturnError.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	case ROSSupplierASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: reject is nil")
		}
		enc_3, err := v.Reject.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_3)
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
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_0)
		return enc_der_0, nil
	case ROSSupplierASChoiceReturnResult:
		if v.ReturnResult == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: returnResult is nil")
		}
		enc_der_1, err := v.ReturnResult.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnResult: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_der_1)
		return enc_der_1, nil
	case ROSSupplierASChoiceReturnError:
		if v.ReturnError == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: returnError is nil")
		}
		enc_der_2, err := v.ReturnError.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding returnError: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_der_2)
		return enc_der_2, nil
	case ROSSupplierASChoiceReject:
		if v.Reject == nil {
			return nil, fmt.Errorf("choice ROSSupplierAS: reject is nil")
		}
		enc_der_3, err := v.Reject.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding reject: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_der_3)
		return enc_der_3, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes ROSSupplierAS from BER/DER format.
func (v *ROSSupplierAS) UnmarshalBER(data []byte) error {
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

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
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
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
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
