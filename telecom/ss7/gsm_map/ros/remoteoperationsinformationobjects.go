// Code generated from ASN.1 module "Remote-Operations-Information-Objects". DO NOT EDIT.

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

// Code choice constants.
const (
	CodeChoiceLocal  = 1
	CodeChoiceGlobal = 2
)

// Code represents the ASN.1 CHOICE type Code.
type Code struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode           `json:"-"`
	Local          *big.Int                  `json:"Local,omitempty"`
	Global         *runtime.ObjectIdentifier `json:"Global,omitempty"`
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
		Global: &v,
	}
}

// Priority represents the ASN.1 type Priority (INTEGER).
type Priority = *big.Int

// MarshalBER encodes Code to BER format.
func (v *Code) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: Code receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *Code) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
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
			return nil, qualifyBERError(encodeErr_enc_0, "local", "encoding", false)
		}
		return enc_0, nil
	case CodeChoiceGlobal:
		if v.Global == nil {
			return nil, fmt.Errorf("%w: choice Code: global is nil", ber.ErrInvalidValue)
		}
		enc_1, oidErr := ber.EncodeObjectIdentifierChecked(*v.Global)
		if oidErr != nil {
			return nil, qualifyBERError(oidErr, "global", "encoding", false)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Code", v.Choice)
	}
}

// MarshalDER encodes Code to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *Code) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Code receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case CodeChoiceLocal:
			return nil, qualifyBERError(err, "local", "encoding", true)
		case CodeChoiceGlobal:
			return nil, qualifyBERError(err, "global", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding Code as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *Code) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes Code from BER/DER format.
func (destination *Code) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: Code destination is nil", ber.ErrInvalidValue)
	}
	var berNextValue_ Code
	v := &berNextValue_
	defer func() {
		if returnErr == nil {
			*destination =
				*v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
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
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *Code, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Code
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "Remote-Operations-Information-Objects.Code", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
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
		return fmt.Errorf("%s: %w", "decoding Code CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Code", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "Code.local", "decoding", false)
	}
	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 6) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "Code.global", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = CodeChoiceLocal
		ber.MarkPreflightTarget(opts, "local", choiceData)
		decVal, _, intErr := ber.DecodeBigInt(choiceData, opts...)
		if intErr != nil {
			return qualifyBERError(intErr, "local", "decoding", false)
		}
		v.Local = decVal
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 && peekTag.Constructed == false {
		v.Choice = CodeChoiceGlobal
		ber.MarkPreflightTarget(opts, "global", choiceData)
		decVal, _, oidErr := ber.DecodeObjectIdentifier(choiceData, opts...)
		if oidErr != nil {
			return qualifyBERError(oidErr, "global", "decoding", false)
		}
		tmp := decVal
		v.Global = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for Code CHOICE", peekTag)
	}
	return nil
}
