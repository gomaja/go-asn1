// Code generated from ASN.1 module "LPPA-PDU-Descriptions". DO NOT EDIT.

package lppa

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

// LPPAPDU choice constants.
const (
	LPPAPDUChoiceInitiatingMessage   = 1
	LPPAPDUChoiceSuccessfulOutcome   = 2
	LPPAPDUChoiceUnsuccessfulOutcome = 3
)

// LPPAPDU represents the ASN.1 CHOICE type LPPA-PDU.
type LPPAPDU struct {
	Choice              int
	PERPadding_         per.CompletePadding         `json:"-"`
	PEROpenTypePadding_ per.CompletePadding         `json:"-"`
	UnknownExtension    *runtime.PERChoiceExtension `json:"UnknownExtension,omitempty"`
	InitiatingMessage   *InitiatingMessage          `json:"InitiatingMessage,omitempty"`
	SuccessfulOutcome   *SuccessfulOutcome          `json:"SuccessfulOutcome,omitempty"`
	UnsuccessfulOutcome *UnsuccessfulOutcome        `json:"UnsuccessfulOutcome,omitempty"`
}

// NewLPPAPDUInitiatingMessage creates a LPPAPDU with the initiatingMessage alternative.
func NewLPPAPDUInitiatingMessage(v InitiatingMessage) LPPAPDU {
	return LPPAPDU{
		Choice:            LPPAPDUChoiceInitiatingMessage,
		InitiatingMessage: &v,
	}
}

// NewLPPAPDUSuccessfulOutcome creates a LPPAPDU with the successfulOutcome alternative.
func NewLPPAPDUSuccessfulOutcome(v SuccessfulOutcome) LPPAPDU {
	return LPPAPDU{
		Choice:            LPPAPDUChoiceSuccessfulOutcome,
		SuccessfulOutcome: &v,
	}
}

// NewLPPAPDUUnsuccessfulOutcome creates a LPPAPDU with the unsuccessfulOutcome alternative.
func NewLPPAPDUUnsuccessfulOutcome(v UnsuccessfulOutcome) LPPAPDU {
	return LPPAPDU{
		Choice:              LPPAPDUChoiceUnsuccessfulOutcome,
		UnsuccessfulOutcome: &v,
	}
}

// InitiatingMessage represents the ASN.1 type InitiatingMessage (SEQUENCE).
type InitiatingMessage struct {
	ProcedureCode     ProcedureCode       `asn1:"tag:0,context,implicit"`
	Criticality       Criticality         `asn1:"tag:1,context,implicit"`
	LppatransactionID LPPATransactionID   `asn1:"tag:2,context,implicit"`
	Value             runtime.RawValue    `asn1:"tag:3,context,explicit" asn1c:"raw-preserve"`
	PERPadding_       per.CompletePadding `asn1:"-" json:"-"`
}

// SuccessfulOutcome represents the ASN.1 type SuccessfulOutcome (SEQUENCE).
type SuccessfulOutcome struct {
	ProcedureCode     ProcedureCode       `asn1:"tag:0,context,implicit"`
	Criticality       Criticality         `asn1:"tag:1,context,implicit"`
	LppatransactionID LPPATransactionID   `asn1:"tag:2,context,implicit"`
	Value             runtime.RawValue    `asn1:"tag:3,context,explicit" asn1c:"raw-preserve"`
	PERPadding_       per.CompletePadding `asn1:"-" json:"-"`
}

// UnsuccessfulOutcome represents the ASN.1 type UnsuccessfulOutcome (SEQUENCE).
type UnsuccessfulOutcome struct {
	ProcedureCode     ProcedureCode       `asn1:"tag:0,context,implicit"`
	Criticality       Criticality         `asn1:"tag:1,context,implicit"`
	LppatransactionID LPPATransactionID   `asn1:"tag:2,context,implicit"`
	Value             runtime.RawValue    `asn1:"tag:3,context,explicit" asn1c:"raw-preserve"`
	PERPadding_       per.CompletePadding `asn1:"-" json:"-"`
}

// MarshalAPER encodes LPPAPDU to APER format.
func (v *LPPAPDU) MarshalAPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *LPPAPDU) MarshalAPERTo(bb *per.BitBuffer) error {
	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("LPPAPDU: known choice %d and unknown extension are both selected", v.Choice)
		}
		if v.UnknownExtension.Index < 0 {
			return fmt.Errorf("LPPAPDU: extension index %d must be non-negative", v.UnknownExtension.Index)
		}
		if err := per.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := per.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index); err != nil {
			return err
		}
		return per.EncodeOpenTypeAligned(bb, v.UnknownExtension.Payload)
	}
	if v.Choice < 1 {
		return fmt.Errorf("LPPAPDU: choice %d must be positive", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := per.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("LPPAPDU: extension choice %d not supported", v.Choice)
	}
	if err := per.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case LPPAPDUChoiceInitiatingMessage:
		if v.InitiatingMessage == nil {
			return fmt.Errorf("choice alternative initiatingMessage is nil")
		}
		if err := v.InitiatingMessage.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding initiatingMessage: %w", err)
		}
	case LPPAPDUChoiceSuccessfulOutcome:
		if v.SuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative successfulOutcome is nil")
		}
		if err := v.SuccessfulOutcome.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding successfulOutcome: %w", err)
		}
	case LPPAPDUChoiceUnsuccessfulOutcome:
		if v.UnsuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative unsuccessfulOutcome is nil")
		}
		if err := v.UnsuccessfulOutcome.MarshalAPERTo(bb); err != nil {
			return fmt.Errorf("encoding unsuccessfulOutcome: %w", err)
		}
	default:
		return fmt.Errorf("unknown LPPAPDU choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes LPPAPDU from APER format.
func (v *LPPAPDU) UnmarshalAPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	if err := v.UnmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LPPAPDU")
	}
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "LPPAPDU")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *LPPAPDU) UnmarshalAPERFrom(bb *per.BitBuffer) error {
	*v = LPPAPDU{}
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
	case LPPAPDUChoiceInitiatingMessage:
		var dec_initiatingmessage InitiatingMessage
		if err := dec_initiatingmessage.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "InitiatingMessage")
		}
		v.InitiatingMessage = &dec_initiatingmessage
	case LPPAPDUChoiceSuccessfulOutcome:
		var dec_successfuloutcome SuccessfulOutcome
		if err := dec_successfuloutcome.UnmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SuccessfulOutcome")
		}
		v.SuccessfulOutcome = &dec_successfuloutcome
	case LPPAPDUChoiceUnsuccessfulOutcome:
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
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *InitiatingMessage) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeIntegerAligned(bb, int64(v.ProcedureCode), int64Ptr(0), int64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.LppatransactionID), int64Ptr(0), int64Ptr(32767), false); err != nil {
		return fmt.Errorf("encoding lppatransactionID: %w", err)
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
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "InitiatingMessage")
	}
	v.PERPadding_ = padding
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
	val_lppatransactionid, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(32767), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LppatransactionID")
	}
	v.LppatransactionID = LPPATransactionID(val_lppatransactionid)
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
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *SuccessfulOutcome) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeIntegerAligned(bb, int64(v.ProcedureCode), int64Ptr(0), int64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.LppatransactionID), int64Ptr(0), int64Ptr(32767), false); err != nil {
		return fmt.Errorf("encoding lppatransactionID: %w", err)
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
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	v.PERPadding_ = padding
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
	val_lppatransactionid, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(32767), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LppatransactionID")
	}
	v.LppatransactionID = LPPATransactionID(val_lppatransactionid)
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
	return bb.CompleteBytesWithPadding(v.PERPadding_)
}

func (v *UnsuccessfulOutcome) MarshalAPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeIntegerAligned(bb, int64(v.ProcedureCode), int64Ptr(0), int64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := per.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := per.EncodeIntegerAligned(bb, int64(v.LppatransactionID), int64Ptr(0), int64Ptr(32767), false); err != nil {
		return fmt.Errorf("encoding lppatransactionID: %w", err)
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
	padding, err := per.CaptureFinalPadding(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	v.PERPadding_ = padding
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
	val_lppatransactionid, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(32767), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LppatransactionID")
	}
	v.LppatransactionID = LPPATransactionID(val_lppatransactionid)
	openData_value, err := per.DecodeOpenTypeAligned(bb)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = runtime.RawValue{Bytes: openData_value}
	return nil
}
