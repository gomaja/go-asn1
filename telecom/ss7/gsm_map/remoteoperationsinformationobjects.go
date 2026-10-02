// Code generated from ASN.1 module "Remote-Operations-Information-Objects". DO NOT EDIT.

package gsm_map

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

// Code choice constants.
const (
	CodeChoiceLocal  = 1
	CodeChoiceGlobal = 2
)

// Code represents the ASN.1 CHOICE type Code.
type Code struct {
	Choice       int
	berOriginal_ []byte                   `json:"-"`
	berSnapshot_ []byte                   `json:"-"`
	Local        *big.Int                 `json:"Local,omitempty"`
	Global       runtime.ObjectIdentifier `json:"Global,omitempty"`
}

// NewCodeLocal creates a Code with the local alternative.
func NewCodeLocal(v *big.Int) Code {
	return Code{
		Choice: CodeChoiceLocal,
		Local:  v,
	}
}

// NewCodeGlobal creates a Code with the global alternative.
func NewCodeGlobal(v runtime.ObjectIdentifier) Code {
	return Code{
		Choice: CodeChoiceGlobal,
		Global: v,
	}
}

// Priority represents the ASN.1 type Priority (INTEGER).
type Priority = *big.Int

// MarshalBER encodes Code to BER format.
func (v *Code) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Code receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *Code) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CodeChoiceLocal:
		if v.Local == nil {
			return nil, fmt.Errorf("%w: choice Code: local is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeBigInt(v.Local)
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding local: %w", encodeErr_enc_0)
		}
		return enc_0, nil
	case CodeChoiceGlobal:
		enc_1, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.Global))
		if oidErr != nil {
			return nil, fmt.Errorf("encoding global: %w", oidErr)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Code", v.Choice)
	}
}

// MarshalDER encodes Code to DER format.
func (v *Code) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Code receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding Code as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes Code from BER/DER format.
func (v *Code) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: Code destination is nil", ber.ErrInvalidValue)
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
	*v = Code{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Code CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Code: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding Code CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Code", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = CodeChoiceLocal
		decVal, _, intErr := ber.DecodeBigInt(choiceData, opts...)
		if intErr != nil {
			return fmt.Errorf("decoding local: %w", intErr)
		}
		v.Local = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 && peekTag.Constructed == false {
		v.Choice = CodeChoiceGlobal
		decVal, _, oidErr := ber.DecodeObjectIdentifier(choiceData, opts...)
		if oidErr != nil {
			return fmt.Errorf("decoding global: %w", oidErr)
		}
		tmp := runtime.ObjectIdentifier(decVal)
		v.Global = tmp
	} else {
		return fmt.Errorf("unknown tag %s for Code CHOICE", peekTag)
	}
	return nil
}
