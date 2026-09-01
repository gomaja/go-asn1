// Code generated from ASN.1 module "Remote-Operations-Information-Objects". DO NOT EDIT.

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

// Code choice constants.
const (
	CodeChoiceLocal  = 1
	CodeChoiceGlobal = 2
)

// Code represents the ASN.1 CHOICE type Code.
type Code struct {
	Choice int
	Local  *big.Int                 `json:"Local,omitempty"`
	Global runtime.ObjectIdentifier `json:"Global,omitempty"`
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
func (v *Code) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case CodeChoiceLocal:
		if v.Local == nil {
			return nil, fmt.Errorf("choice Code: local is nil")
		}
		enc_0 := ber.EncodeBigInt(v.Local)
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
	return v.MarshalBER()
}

// UnmarshalBER decodes Code from BER/DER format.
func (v *Code) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for Code CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Code: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding Code CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Code", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
		v.Choice = CodeChoiceLocal
		decVal, _, intErr := ber.DecodeBigInt(choiceData)
		if intErr != nil {
			return fmt.Errorf("decoding local: %w", intErr)
		}
		v.Local = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 {
		v.Choice = CodeChoiceGlobal
		decVal, _, oidErr := ber.DecodeObjectIdentifier(choiceData)
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
