// Code generated from ASN.1 module "S1AP-PDU-Descriptions". DO NOT EDIT.

package s1ap

import (
	"fmt"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = per.NewBitBuffer
)

// S1APPDU choice constants.
const (
	S1APPDUChoiceInitiatingMessage   = 1
	S1APPDUChoiceSuccessfulOutcome   = 2
	S1APPDUChoiceUnsuccessfulOutcome = 3
)

// S1APPDU represents the ASN.1 CHOICE type S1AP-PDU.
type S1APPDU struct {
	Choice              int
	UnknownExtension    *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	InitiatingMessage   *InitiatingMessage          `json:"InitiatingMessage,omitempty"`
	SuccessfulOutcome   *SuccessfulOutcome          `json:"SuccessfulOutcome,omitempty"`
	UnsuccessfulOutcome *UnsuccessfulOutcome        `json:"UnsuccessfulOutcome,omitempty"`
}

// NewS1APPDUInitiatingMessage creates a S1APPDU with the initiatingMessage alternative.
func NewS1APPDUInitiatingMessage(v InitiatingMessage) S1APPDU {
	return S1APPDU{
		Choice:            S1APPDUChoiceInitiatingMessage,
		InitiatingMessage: &v,
	}
}

// NewS1APPDUSuccessfulOutcome creates a S1APPDU with the successfulOutcome alternative.
func NewS1APPDUSuccessfulOutcome(v SuccessfulOutcome) S1APPDU {
	return S1APPDU{
		Choice:            S1APPDUChoiceSuccessfulOutcome,
		SuccessfulOutcome: &v,
	}
}

// NewS1APPDUUnsuccessfulOutcome creates a S1APPDU with the unsuccessfulOutcome alternative.
func NewS1APPDUUnsuccessfulOutcome(v UnsuccessfulOutcome) S1APPDU {
	return S1APPDU{
		Choice:              S1APPDUChoiceUnsuccessfulOutcome,
		UnsuccessfulOutcome: &v,
	}
}

// InitiatingMessage represents the ASN.1 type InitiatingMessage (SEQUENCE).
type InitiatingMessage struct {
	ProcedureCode ProcedureCode    `asn1:"tag:0,context,implicit"`
	Criticality   Criticality      `asn1:"tag:1,context,implicit"`
	Value         runtime.RawValue `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
}

// SuccessfulOutcome represents the ASN.1 type SuccessfulOutcome (SEQUENCE).
type SuccessfulOutcome struct {
	ProcedureCode ProcedureCode    `asn1:"tag:0,context,implicit"`
	Criticality   Criticality      `asn1:"tag:1,context,implicit"`
	Value         runtime.RawValue `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
}

// UnsuccessfulOutcome represents the ASN.1 type UnsuccessfulOutcome (SEQUENCE).
type UnsuccessfulOutcome struct {
	ProcedureCode ProcedureCode    `asn1:"tag:0,context,implicit"`
	Criticality   Criticality      `asn1:"tag:1,context,implicit"`
	Value         runtime.RawValue `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
}

// MarshalAPER encodes S1APPDU to APER format.
func (v *S1APPDU) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *S1APPDU) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("S1APPDU: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("S1APPDU: extension index %d must be non-negative", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	isExtension := v.Choice > 3
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("S1APPDU: extension choice %d not supported", v.Choice)
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case S1APPDUChoiceInitiatingMessage:
		if v.InitiatingMessage == nil {
			return fmt.Errorf("choice alternative initiatingMessage is nil")
		}
		if err := v.InitiatingMessage.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding initiatingMessage: %w", err)
		}
	case S1APPDUChoiceSuccessfulOutcome:
		if v.SuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative successfulOutcome is nil")
		}
		if err := v.SuccessfulOutcome.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding successfulOutcome: %w", err)
		}
	case S1APPDUChoiceUnsuccessfulOutcome:
		if v.UnsuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative unsuccessfulOutcome is nil")
		}
		if err := v.UnsuccessfulOutcome.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding unsuccessfulOutcome: %w", err)
		}
	default:
		return fmt.Errorf("unknown S1APPDU choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes S1APPDU from APER format.
func (v *S1APPDU) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1APPDU")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "S1APPDU")
	}
	return nil
}

func (v *S1APPDU) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = S1APPDU{}
	isExtension, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := per.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openData, err := per.DecodeOpenTypeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &runtime.PERChoiceExtension{Index: extIdx, Payload: append([]byte(nil), openData...)}
		return nil
	}
	idx, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case S1APPDUChoiceInitiatingMessage:
		var dec_initiatingmessage InitiatingMessage
		if err := dec_initiatingmessage.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "InitiatingMessage")
		}
		v.InitiatingMessage = &dec_initiatingmessage
	case S1APPDUChoiceSuccessfulOutcome:
		var dec_successfuloutcome SuccessfulOutcome
		if err := dec_successfuloutcome.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SuccessfulOutcome")
		}
		v.SuccessfulOutcome = &dec_successfuloutcome
	case S1APPDUChoiceUnsuccessfulOutcome:
		var dec_unsuccessfuloutcome UnsuccessfulOutcome
		if err := dec_unsuccessfuloutcome.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
		}
		v.UnsuccessfulOutcome = &dec_unsuccessfuloutcome
	}
	return nil
}

// MarshalAPER encodes InitiatingMessage to APER format.
func (v *InitiatingMessage) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *InitiatingMessage) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeIntegerAligned(bb, int64(v.ProcedureCode), int64Ptr(0), int64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := per.EncodeOpenTypeAligned(bb, v.Value.Bytes); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes InitiatingMessage from APER format.
func (v *InitiatingMessage) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitiatingMessage")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitiatingMessage")
	}
	return nil
}

func (v *InitiatingMessage) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = InitiatingMessage{}
	val_procedurecode, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProcedureCode")
	}
	v.ProcedureCode = ProcedureCode(val_procedurecode)
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Criticality")
	}
	v.Criticality = Criticality(val_criticality)
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	return nil
}

// MarshalAPER encodes SuccessfulOutcome to APER format.
func (v *SuccessfulOutcome) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *SuccessfulOutcome) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeIntegerAligned(bb, int64(v.ProcedureCode), int64Ptr(0), int64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := per.EncodeOpenTypeAligned(bb, v.Value.Bytes); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes SuccessfulOutcome from APER format.
func (v *SuccessfulOutcome) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	return nil
}

func (v *SuccessfulOutcome) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = SuccessfulOutcome{}
	val_procedurecode, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProcedureCode")
	}
	v.ProcedureCode = ProcedureCode(val_procedurecode)
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Criticality")
	}
	v.Criticality = Criticality(val_criticality)
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	return nil
}

// MarshalAPER encodes UnsuccessfulOutcome to APER format.
func (v *UnsuccessfulOutcome) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytes(), nil
}

func (v *UnsuccessfulOutcome) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeIntegerAligned(bb, int64(v.ProcedureCode), int64Ptr(0), int64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := per.EncodeOpenTypeAligned(bb, v.Value.Bytes); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes UnsuccessfulOutcome from APER format.
func (v *UnsuccessfulOutcome) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	if err := per.ValidateFinalPadding(bb); err != nil {
		return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	return nil
}

func (v *UnsuccessfulOutcome) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = UnsuccessfulOutcome{}
	val_procedurecode, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProcedureCode")
	}
	v.ProcedureCode = ProcedureCode(val_procedurecode)
	val_criticality, err := per.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Criticality")
	}
	v.Criticality = Criticality(val_criticality)
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	return nil
}
