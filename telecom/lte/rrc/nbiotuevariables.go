// Code generated from ASN.1 module "NBIOT-UE-Variables". DO NOT EDIT.

package rrc

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

// VarANRMeasConfigNBR16 represents the ASN.1 type VarANRMeasConfigNBR16 (SEQUENCE).
type VarANRMeasConfigNBR16 struct {
	AnrQualityThresholdR16  NRSRPRangeNBR14     `asn1:"tag:0,context,implicit"`
	AnrCarrierListR16       ANRCarrierListNBR16 `asn1:"tag:1,context,implicit"`
	AnrCarrierListR16Indef_ bool                `asn1:"-" json:"-"`
}

// VarANRMeasReportNBR16 represents the ASN.1 type VarANRMeasReportNBR16 (SEQUENCE).
type VarANRMeasReportNBR16 struct {
	PlmnIdentityListR16       PLMNIdentityList3R11                   `asn1:"tag:0,context,implicit"`
	PlmnIdentityListR16Indef_ bool                                   `asn1:"-" json:"-"`
	ServCellIdentityR16       CellGlobalIdEUTRA                      `asn1:"tag:1,context,implicit"`
	MeasResultServCellR16     MeasResultServCellNBR14                `asn1:"tag:2,context,implicit"`
	RelativeTimeStampR16      int64                                  `asn1:"tag:3,context,implicit"`
	MeasResultListR16         VarANRMeasReportNBR16MeasResultListR16 `asn1:"tag:4,context,implicit"`
	MeasResultListR16Indef_   bool                                   `asn1:"-" json:"-"`
}

// VarRLFReportNBR16 represents the ASN.1 type VarRLFReportNBR16 (SEQUENCE).
type VarRLFReportNBR16 struct {
	RlfReportR16              RLFReportNBR16       `asn1:"tag:0,context,implicit"`
	PlmnIdentityListR16       PLMNIdentityList3R11 `asn1:"tag:1,context,implicit"`
	PlmnIdentityListR16Indef_ bool                 `asn1:"-" json:"-"`
}

// VarShortMACInputNBR13 represents the ASN.1 type VarShortMACInputNBR13 (SEQUENCE).
type VarShortMACInputNBR13 = VarShortMACInput

// VarShortResumeMACInputNBR13 represents the ASN.1 type VarShortResumeMACInputNBR13 (SEQUENCE).
type VarShortResumeMACInputNBR13 = VarShortResumeMACInputR13

// VarANRMeasReportNBR16MeasResultListR16 represents the ASN.1 type VarANRMeasReportNBR16MeasResultListR16 (SEQUENCE_OF).
type VarANRMeasReportNBR16MeasResultListR16 = []ANRMeasResultNBR16

// MarshalUPER encodes VarANRMeasConfigNBR16 to UPER format.
func (v *VarANRMeasConfigNBR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *VarANRMeasConfigNBR16) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.AnrQualityThresholdR16), int64Ptr(0), int64Ptr(113), false); err != nil {
		return fmt.Errorf("encoding anr-QualityThreshold-r16: %w", err)
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.AnrCarrierListR16)), 1, 2); err != nil {
		return fmt.Errorf("encoding anr-CarrierList-r16 length: %w", err)
	}
	for _, elem := range v.AnrCarrierListR16 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding anr-CarrierList-r16 element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarANRMeasConfigNBR16 from UPER format.
func (v *VarANRMeasConfigNBR16) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarANRMeasConfigNBR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	val_anrqualitythresholdr16, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(113), false)
	if err != nil {
		return fmt.Errorf("decoding anr-QualityThreshold-r16: %w", err)
	}
	v.AnrQualityThresholdR16 = NRSRPRangeNBR14(val_anrqualitythresholdr16)
	seqLen_anrcarrierlistr16, err := per.DecodeConstrainedWholeNumber(bb, 1, 2)
	if err != nil {
		return fmt.Errorf("decoding anr-CarrierList-r16 length: %w", err)
	}
	v.AnrCarrierListR16 = make(ANRCarrierListNBR16, seqLen_anrcarrierlistr16)
	for i := int64(0); i < seqLen_anrcarrierlistr16; i++ {
		if err := v.AnrCarrierListR16[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding anr-CarrierList-r16 element: %w", err)
		}
	}
	return nil
}

// MarshalUPER encodes VarANRMeasReportNBR16 to UPER format.
func (v *VarANRMeasReportNBR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *VarANRMeasReportNBR16) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.PlmnIdentityListR16)), 1, 16); err != nil {
		return fmt.Errorf("encoding plmn-IdentityList-r16 length: %w", err)
	}
	for _, elem := range v.PlmnIdentityListR16 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding plmn-IdentityList-r16 element: %w", err)
		}
	}
	if err := v.ServCellIdentityR16.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding servCellIdentity-r16: %w", err)
	}
	if err := v.MeasResultServCellR16.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding measResultServCell-r16: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.RelativeTimeStampR16), int64Ptr(0), int64Ptr(95), false); err != nil {
		return fmt.Errorf("encoding relativeTimeStamp-r16: %w", err)
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.MeasResultListR16)), 1, 2); err != nil {
		return fmt.Errorf("encoding measResultList-r16 length: %w", err)
	}
	for _, elem := range v.MeasResultListR16 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding measResultList-r16 element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarANRMeasReportNBR16 from UPER format.
func (v *VarANRMeasReportNBR16) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarANRMeasReportNBR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	seqLen_plmnidentitylistr16, err := per.DecodeConstrainedWholeNumber(bb, 1, 16)
	if err != nil {
		return fmt.Errorf("decoding plmn-IdentityList-r16 length: %w", err)
	}
	v.PlmnIdentityListR16 = make(PLMNIdentityList3R11, seqLen_plmnidentitylistr16)
	for i := int64(0); i < seqLen_plmnidentitylistr16; i++ {
		if err := v.PlmnIdentityListR16[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding plmn-IdentityList-r16 element: %w", err)
		}
	}
	if err := v.ServCellIdentityR16.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding servCellIdentity-r16: %w", err)
	}
	if err := v.MeasResultServCellR16.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding measResultServCell-r16: %w", err)
	}
	val_relativetimestampr16, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(95), false)
	if err != nil {
		return fmt.Errorf("decoding relativeTimeStamp-r16: %w", err)
	}
	v.RelativeTimeStampR16 = val_relativetimestampr16
	seqLen_measresultlistr16, err := per.DecodeConstrainedWholeNumber(bb, 1, 2)
	if err != nil {
		return fmt.Errorf("decoding measResultList-r16 length: %w", err)
	}
	v.MeasResultListR16 = make(VarANRMeasReportNBR16MeasResultListR16, seqLen_measresultlistr16)
	for i := int64(0); i < seqLen_measresultlistr16; i++ {
		if err := v.MeasResultListR16[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding measResultList-r16 element: %w", err)
		}
	}
	return nil
}

// MarshalUPER encodes VarRLFReportNBR16 to UPER format.
func (v *VarRLFReportNBR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func (v *VarRLFReportNBR16) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.RlfReportR16.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding rlf-Report-r16: %w", err)
	}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.PlmnIdentityListR16)), 1, 16); err != nil {
		return fmt.Errorf("encoding plmn-IdentityList-r16 length: %w", err)
	}
	for _, elem := range v.PlmnIdentityListR16 {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding plmn-IdentityList-r16 element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPER decodes VarRLFReportNBR16 from UPER format.
func (v *VarRLFReportNBR16) UnmarshalUPER(data []byte) error {
	bb := per.NewBitBufferFromBytes(data)
	return v.UnmarshalUPERFrom(bb)
}

func (v *VarRLFReportNBR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	if err := v.RlfReportR16.UnmarshalUPERFrom(bb); err != nil {
		return fmt.Errorf("decoding rlf-Report-r16: %w", err)
	}
	seqLen_plmnidentitylistr16, err := per.DecodeConstrainedWholeNumber(bb, 1, 16)
	if err != nil {
		return fmt.Errorf("decoding plmn-IdentityList-r16 length: %w", err)
	}
	v.PlmnIdentityListR16 = make(PLMNIdentityList3R11, seqLen_plmnidentitylistr16)
	for i := int64(0); i < seqLen_plmnidentitylistr16; i++ {
		if err := v.PlmnIdentityListR16[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding plmn-IdentityList-r16 element: %w", err)
		}
	}
	return nil
}

type asn1cUPERVarANRMeasReportNBR16MeasResultListR16ListValue struct {
	Value VarANRMeasReportNBR16MeasResultListR16
}

// MarshalUPERVarANRMeasReportNBR16MeasResultListR16 encodes a VarANRMeasReportNBR16MeasResultListR16 list to UPER.
func MarshalUPERVarANRMeasReportNBR16MeasResultListR16(list VarANRMeasReportNBR16MeasResultListR16) ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := marshalUPERVarANRMeasReportNBR16MeasResultListR16To(list, bb); err != nil {
		return nil, err
	}
	return bb.Bytes(), nil
}

func marshalUPERVarANRMeasReportNBR16MeasResultListR16To(list VarANRMeasReportNBR16MeasResultListR16, bb *per.BitBuffer) error {
	v := asn1cUPERVarANRMeasReportNBR16MeasResultListR16ListValue{Value: list}
	if err := per.EncodeConstrainedWholeNumber(bb, int64(len(v.Value)), 1, 2); err != nil {
		return fmt.Errorf("encoding value length: %w", err)
	}
	for _, elem := range v.Value {
		if err := elem.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding value element: %w", err)
		}
	}
	return nil
}

// UnmarshalUPERVarANRMeasReportNBR16MeasResultListR16 decodes a VarANRMeasReportNBR16MeasResultListR16 list from UPER.
func UnmarshalUPERVarANRMeasReportNBR16MeasResultListR16(data []byte) (VarANRMeasReportNBR16MeasResultListR16, error) {
	bb := per.NewBitBufferFromBytes(data)
	return unmarshalUPERVarANRMeasReportNBR16MeasResultListR16From(bb)
}

func unmarshalUPERVarANRMeasReportNBR16MeasResultListR16From(bb *per.BitBuffer) (VarANRMeasReportNBR16MeasResultListR16, error) {
	var v asn1cUPERVarANRMeasReportNBR16MeasResultListR16ListValue
	if err := unmarshalUPERVarANRMeasReportNBR16MeasResultListR16Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERVarANRMeasReportNBR16MeasResultListR16Into(v *asn1cUPERVarANRMeasReportNBR16MeasResultListR16ListValue, bb *per.BitBuffer) error {
	seqLen_value, err := per.DecodeConstrainedWholeNumber(bb, 1, 2)
	if err != nil {
		return fmt.Errorf("decoding value length: %w", err)
	}
	v.Value = make(VarANRMeasReportNBR16MeasResultListR16, seqLen_value)
	for i := int64(0); i < seqLen_value; i++ {
		if err := v.Value[i].UnmarshalUPERFrom(bb); err != nil {
			return fmt.Errorf("decoding value element: %w", err)
		}
	}
	return nil
}
