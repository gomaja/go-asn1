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

// VarANRMeasConfigNBR16 represents the ASN.1 type VarANR-MeasConfig-NB-r16 (SEQUENCE).
type VarANRMeasConfigNBR16 struct {
	AnrQualityThresholdR16  NRSRPRangeNBR14     `asn1:"tag:0,context,implicit"`
	AnrCarrierListR16       ANRCarrierListNBR16 `asn1:"tag:1,context,implicit"`
	AnrCarrierListR16Indef_ bool                `asn1:"-" json:"-"`
	PERPadding_             per.FinalPadding    `asn1:"-" json:"-"`
}

// VarANRMeasReportNBR16 represents the ASN.1 type VarANR-MeasReport-NB-r16 (SEQUENCE).
type VarANRMeasReportNBR16 struct {
	PlmnIdentityListR16       PLMNIdentityList3R11                   `asn1:"tag:0,context,implicit"`
	PlmnIdentityListR16Indef_ bool                                   `asn1:"-" json:"-"`
	ServCellIdentityR16       CellGlobalIdEUTRA                      `asn1:"tag:1,context,implicit"`
	MeasResultServCellR16     MeasResultServCellNBR14                `asn1:"tag:2,context,implicit"`
	RelativeTimeStampR16      int64                                  `asn1:"tag:3,context,implicit"`
	MeasResultListR16         VarANRMeasReportNBR16MeasResultListR16 `asn1:"tag:4,context,implicit"`
	MeasResultListR16Indef_   bool                                   `asn1:"-" json:"-"`
	PERPadding_               per.FinalPadding                       `asn1:"-" json:"-"`
}

// VarRLFReportNBR16 represents the ASN.1 type VarRLF-Report-NB-r16 (SEQUENCE).
type VarRLFReportNBR16 struct {
	RlfReportR16              RLFReportNBR16       `asn1:"tag:0,context,implicit"`
	PlmnIdentityListR16       PLMNIdentityList3R11 `asn1:"tag:1,context,implicit"`
	PlmnIdentityListR16Indef_ bool                 `asn1:"-" json:"-"`
	PERPadding_               per.FinalPadding     `asn1:"-" json:"-"`
}

// VarShortMACInputNBR13 represents the ASN.1 type VarShortMAC-Input-NB-r13 (SEQUENCE).
type VarShortMACInputNBR13 = VarShortMACInput

// VarShortResumeMACInputNBR13 represents the ASN.1 type VarShortResumeMAC-Input-NB-r13 (SEQUENCE).
type VarShortResumeMACInputNBR13 = VarShortResumeMACInputR13

// VarANRMeasReportNBR16MeasResultListR16 represents the ASN.1 type VarANR-MeasReport-NB-r16-measResultList-r16 (SEQUENCE_OF).

type VarANRMeasReportNBR16MeasResultListR16 = []ANRMeasResultNBR16

// MarshalUPER encodes VarANRMeasConfigNBR16 to UPER format.
func (v *VarANRMeasConfigNBR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *VarANRMeasConfigNBR16) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeInteger(bb, int64(v.AnrQualityThresholdR16), int64Ptr(0), int64Ptr(113), false); err != nil {
		return fmt.Errorf("encoding anr-QualityThreshold-r16: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.AnrCarrierListR16)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, false, func(fragmentOffset_anrcarrierlistr16, fragmentLength_anrcarrierlistr16 int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_anrcarrierlistr16 < 0 || fragmentOffset_anrcarrierlistr16 > int64(len(v.AnrCarrierListR16)) || fragmentLength_anrcarrierlistr16 < 0 || fragmentLength_anrcarrierlistr16 > int64(len(v.AnrCarrierListR16[fragmentOffset_anrcarrierlistr16:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.AnrCarrierListR16[fragmentOffset_anrcarrierlistr16 : fragmentOffset_anrcarrierlistr16+fragmentLength_anrcarrierlistr16] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding anr-CarrierList-r16 element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding anr-CarrierList-r16: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarANRMeasConfigNBR16 from UPER format.
func (v *VarANRMeasConfigNBR16) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes VarANRMeasConfigNBR16 with explicit receiver options.
func (v *VarANRMeasConfigNBR16) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarANRMeasConfigNBR16")
	}
	padding, err := per.CaptureFinalBits(bb, "VarANRMeasConfigNBR16")
	if err != nil {
		return runtime.WrapDecodePath(err, "VarANRMeasConfigNBR16")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *VarANRMeasConfigNBR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarANRMeasConfigNBR16{}
	val_anrqualitythresholdr16, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(113), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "AnrQualityThresholdR16")
	}
	v.AnrQualityThresholdR16 = NRSRPRangeNBR14(val_anrqualitythresholdr16)
	v.AnrCarrierListR16 = make(ANRCarrierListNBR16, 0)
	_, errCollection_anrcarrierlistr16 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, false, func(fragmentOffset_anrcarrierlistr16, fragmentLength_anrcarrierlistr16 int64) error {
		// arithmetic pattern UPER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_uper.go:1208
		if fragmentOffset_anrcarrierlistr16 < 0 || fragmentLength_anrcarrierlistr16 < 0 || fragmentLength_anrcarrierlistr16 > int64(^uint(0)>>1) || fragmentOffset_anrcarrierlistr16 > int64(^uint(0)>>1)-fragmentLength_anrcarrierlistr16 {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_anrcarrierlistr16; i++ {
			var elem ANRCarrierNBR16
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("AnrCarrierListR16[%d]", fragmentOffset_anrcarrierlistr16+i))
			}
			v.AnrCarrierListR16 = append(v.AnrCarrierListR16, elem)
		}
		return nil
	})
	if errCollection_anrcarrierlistr16 != nil {
		return runtime.WrapDecodePath(errCollection_anrcarrierlistr16, "AnrCarrierListR16")
	}
	return nil
}

// MarshalUPER encodes VarANRMeasReportNBR16 to UPER format.
func (v *VarANRMeasReportNBR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *VarANRMeasReportNBR16) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := per.EncodeCollection(bb, int64(len(v.PlmnIdentityListR16)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, false, func(fragmentOffset_plmnidentitylistr16, fragmentLength_plmnidentitylistr16 int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_plmnidentitylistr16 < 0 || fragmentOffset_plmnidentitylistr16 > int64(len(v.PlmnIdentityListR16)) || fragmentLength_plmnidentitylistr16 < 0 || fragmentLength_plmnidentitylistr16 > int64(len(v.PlmnIdentityListR16[fragmentOffset_plmnidentitylistr16:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PlmnIdentityListR16[fragmentOffset_plmnidentitylistr16 : fragmentOffset_plmnidentitylistr16+fragmentLength_plmnidentitylistr16] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding plmn-IdentityList-r16 element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding plmn-IdentityList-r16: %w", err)
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
	if err := per.EncodeCollection(bb, int64(len(v.MeasResultListR16)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, false, func(fragmentOffset_measresultlistr16, fragmentLength_measresultlistr16 int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_measresultlistr16 < 0 || fragmentOffset_measresultlistr16 > int64(len(v.MeasResultListR16)) || fragmentLength_measresultlistr16 < 0 || fragmentLength_measresultlistr16 > int64(len(v.MeasResultListR16[fragmentOffset_measresultlistr16:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.MeasResultListR16[fragmentOffset_measresultlistr16 : fragmentOffset_measresultlistr16+fragmentLength_measresultlistr16] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding measResultList-r16 element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding measResultList-r16: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarANRMeasReportNBR16 from UPER format.
func (v *VarANRMeasReportNBR16) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes VarANRMeasReportNBR16 with explicit receiver options.
func (v *VarANRMeasReportNBR16) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarANRMeasReportNBR16")
	}
	padding, err := per.CaptureFinalBits(bb, "VarANRMeasReportNBR16")
	if err != nil {
		return runtime.WrapDecodePath(err, "VarANRMeasReportNBR16")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *VarANRMeasReportNBR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarANRMeasReportNBR16{}
	v.PlmnIdentityListR16 = make(PLMNIdentityList3R11, 0)
	_, errCollection_plmnidentitylistr16 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, false, func(fragmentOffset_plmnidentitylistr16, fragmentLength_plmnidentitylistr16 int64) error {
		// arithmetic pattern UPER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_uper.go:1208
		if fragmentOffset_plmnidentitylistr16 < 0 || fragmentLength_plmnidentitylistr16 < 0 || fragmentLength_plmnidentitylistr16 > int64(^uint(0)>>1) || fragmentOffset_plmnidentitylistr16 > int64(^uint(0)>>1)-fragmentLength_plmnidentitylistr16 {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_plmnidentitylistr16; i++ {
			var elem PLMNIdentity
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PlmnIdentityListR16[%d]", fragmentOffset_plmnidentitylistr16+i))
			}
			v.PlmnIdentityListR16 = append(v.PlmnIdentityListR16, elem)
		}
		return nil
	})
	if errCollection_plmnidentitylistr16 != nil {
		return runtime.WrapDecodePath(errCollection_plmnidentitylistr16, "PlmnIdentityListR16")
	}
	if err := v.ServCellIdentityR16.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ServCellIdentityR16")
	}
	if err := v.MeasResultServCellR16.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MeasResultServCellR16")
	}
	val_relativetimestampr16, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(95), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "RelativeTimeStampR16")
	}
	v.RelativeTimeStampR16 = val_relativetimestampr16
	v.MeasResultListR16 = make(VarANRMeasReportNBR16MeasResultListR16, 0)
	_, errCollection_measresultlistr16 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, false, func(fragmentOffset_measresultlistr16, fragmentLength_measresultlistr16 int64) error {
		// arithmetic pattern UPER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_uper.go:1208
		if fragmentOffset_measresultlistr16 < 0 || fragmentLength_measresultlistr16 < 0 || fragmentLength_measresultlistr16 > int64(^uint(0)>>1) || fragmentOffset_measresultlistr16 > int64(^uint(0)>>1)-fragmentLength_measresultlistr16 {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_measresultlistr16; i++ {
			var elem ANRMeasResultNBR16
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("MeasResultListR16[%d]", fragmentOffset_measresultlistr16+i))
			}
			v.MeasResultListR16 = append(v.MeasResultListR16, elem)
		}
		return nil
	})
	if errCollection_measresultlistr16 != nil {
		return runtime.WrapDecodePath(errCollection_measresultlistr16, "MeasResultListR16")
	}
	return nil
}

// MarshalUPER encodes VarRLFReportNBR16 to UPER format.
func (v *VarRLFReportNBR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *VarRLFReportNBR16) MarshalUPERTo(bb *per.BitBuffer) error {
	if err := v.RlfReportR16.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding rlf-Report-r16: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.PlmnIdentityListR16)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, false, func(fragmentOffset_plmnidentitylistr16, fragmentLength_plmnidentitylistr16 int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_plmnidentitylistr16 < 0 || fragmentOffset_plmnidentitylistr16 > int64(len(v.PlmnIdentityListR16)) || fragmentLength_plmnidentitylistr16 < 0 || fragmentLength_plmnidentitylistr16 > int64(len(v.PlmnIdentityListR16[fragmentOffset_plmnidentitylistr16:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PlmnIdentityListR16[fragmentOffset_plmnidentitylistr16 : fragmentOffset_plmnidentitylistr16+fragmentLength_plmnidentitylistr16] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding plmn-IdentityList-r16 element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding plmn-IdentityList-r16: %w", err)
	}
	return nil
}

// UnmarshalUPER decodes VarRLFReportNBR16 from UPER format.
func (v *VarRLFReportNBR16) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes VarRLFReportNBR16 with explicit receiver options.
func (v *VarRLFReportNBR16) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "VarRLFReportNBR16")
	}
	padding, err := per.CaptureFinalBits(bb, "VarRLFReportNBR16")
	if err != nil {
		return runtime.WrapDecodePath(err, "VarRLFReportNBR16")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *VarRLFReportNBR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = VarRLFReportNBR16{}
	if err := v.RlfReportR16.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RlfReportR16")
	}
	v.PlmnIdentityListR16 = make(PLMNIdentityList3R11, 0)
	_, errCollection_plmnidentitylistr16 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, false, func(fragmentOffset_plmnidentitylistr16, fragmentLength_plmnidentitylistr16 int64) error {
		// arithmetic pattern UPER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_uper.go:1208
		if fragmentOffset_plmnidentitylistr16 < 0 || fragmentLength_plmnidentitylistr16 < 0 || fragmentLength_plmnidentitylistr16 > int64(^uint(0)>>1) || fragmentOffset_plmnidentitylistr16 > int64(^uint(0)>>1)-fragmentLength_plmnidentitylistr16 {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_plmnidentitylistr16; i++ {
			var elem PLMNIdentity
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PlmnIdentityListR16[%d]", fragmentOffset_plmnidentitylistr16+i))
			}
			v.PlmnIdentityListR16 = append(v.PlmnIdentityListR16, elem)
		}
		return nil
	})
	if errCollection_plmnidentitylistr16 != nil {
		return runtime.WrapDecodePath(errCollection_plmnidentitylistr16, "PlmnIdentityListR16")
	}
	return nil
}

type asn1cUPERVarANRMeasReportNBR16MeasResultListR16ListValue struct {
	Value VarANRMeasReportNBR16MeasResultListR16
}

// VarANRMeasReportNBR16MeasResultListR16Complete carries a complete VarANRMeasReportNBR16MeasResultListR16 encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type VarANRMeasReportNBR16MeasResultListR16Complete struct {
	Value       VarANRMeasReportNBR16MeasResultListR16
	PERPadding_ per.FinalPadding `json:"-"`
}

func (v *VarANRMeasReportNBR16MeasResultListR16Complete) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := MarshalUPERVarANRMeasReportNBR16MeasResultListR16To(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

// UnmarshalUPER decodes a complete VarANRMeasReportNBR16MeasResultListR16 strictly.
func (v *VarANRMeasReportNBR16MeasResultListR16Complete) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes a complete VarANRMeasReportNBR16MeasResultListR16 with explicit receiver options.
func (v *VarANRMeasReportNBR16MeasResultListR16Complete) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	value, err := UnmarshalUPERVarANRMeasReportNBR16MeasResultListR16From(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "VarANRMeasReportNBR16MeasResultListR16")
	}
	padding, err := per.CaptureFinalBits(bb, "VarANRMeasReportNBR16MeasResultListR16")
	if err != nil {
		return runtime.WrapDecodePath(err, "VarANRMeasReportNBR16MeasResultListR16")
	}
	v.Value, v.PERPadding_ = value, padding
	return nil
}

// MarshalUPERVarANRMeasReportNBR16MeasResultListR16 encodes a VarANRMeasReportNBR16MeasResultListR16 list to UPER.
func MarshalUPERVarANRMeasReportNBR16MeasResultListR16(list VarANRMeasReportNBR16MeasResultListR16Complete) ([]byte, error) {
	return list.MarshalUPER()
}

// MarshalUPERVarANRMeasReportNBR16MeasResultListR16To appends a VarANRMeasReportNBR16MeasResultListR16 list to bb.
func MarshalUPERVarANRMeasReportNBR16MeasResultListR16To(list VarANRMeasReportNBR16MeasResultListR16, bb *per.BitBuffer) error {
	v := asn1cUPERVarANRMeasReportNBR16MeasResultListR16ListValue{Value: list}
	if err := per.EncodeCollection(bb, int64(len(v.Value)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalUPERVarANRMeasReportNBR16MeasResultListR16 decodes a VarANRMeasReportNBR16MeasResultListR16 list from UPER.
func UnmarshalUPERVarANRMeasReportNBR16MeasResultListR16(data []byte) (VarANRMeasReportNBR16MeasResultListR16Complete, error) {
	var value VarANRMeasReportNBR16MeasResultListR16Complete
	if err := value.UnmarshalUPER(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalUPERVarANRMeasReportNBR16MeasResultListR16From decodes a VarANRMeasReportNBR16MeasResultListR16 list from bb.
func UnmarshalUPERVarANRMeasReportNBR16MeasResultListR16From(bb *per.BitBuffer) (VarANRMeasReportNBR16MeasResultListR16, error) {
	var v asn1cUPERVarANRMeasReportNBR16MeasResultListR16ListValue
	if err := unmarshalUPERVarANRMeasReportNBR16MeasResultListR16Into(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

func unmarshalUPERVarANRMeasReportNBR16MeasResultListR16Into(v *asn1cUPERVarANRMeasReportNBR16MeasResultListR16ListValue, bb *per.BitBuffer) error {
	v.Value = make(VarANRMeasReportNBR16MeasResultListR16, 0)
	_, errCollection_value := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, false, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern UPER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_uper.go:1208
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem ANRMeasResultNBR16
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			v.Value = append(v.Value, elem)
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}
