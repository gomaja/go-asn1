// Code generated from ASN.1 module "LPP-Broadcast-Definitions". DO NOT EDIT.

package lpp

import (
	"fmt"
	"time"

	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = per.NewBitBuffer
)

// AssistanceDataSIBelementR15 represents the ASN.1 type AssistanceDataSIBelement-r15 (SEQUENCE).
type AssistanceDataSIBelementR15 struct {
	ValueTagR15              *int64                `asn1:"tag:0,context,implicit,optional" json:"ValueTagR15,omitempty"`
	ExpirationTimeR15        *time.Time            `asn1:"tag:1,context,implicit,optional" json:"ExpirationTimeR15,omitempty"`
	CipheringKeyDataR15      *CipheringKeyDataR15  `asn1:"tag:2,context,implicit,optional" json:"CipheringKeyDataR15,omitempty"`
	SegmentationInfoR15      *SegmentationInfoR15  `asn1:"tag:3,context,implicit,optional" json:"SegmentationInfoR15,omitempty"`
	AssistanceDataElementR15 []byte                `asn1:"tag:4,context,implicit"`
	ExtCount_                int64                 `asn1:"-" json:"-"`
	ExtPresent_              []bool                `asn1:"-" json:"-"`
	ExtData_                 [][]byte              `asn1:"-" json:"-"`
	PERPadding_              per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_           []per.CompletePadding `asn1:"-" json:"-"`
}

// CipheringKeyDataR15 represents the ASN.1 type CipheringKeyData-r15 (SEQUENCE).
type CipheringKeyDataR15 struct {
	CipherSetIDR15 int64                 `asn1:"tag:0,context,implicit"`
	D0R15          runtime.BitString     `asn1:"tag:1,context,implicit"`
	ExtCount_      int64                 `asn1:"-" json:"-"`
	ExtPresent_    []bool                `asn1:"-" json:"-"`
	ExtData_       [][]byte              `asn1:"-" json:"-"`
	PERPadding_    per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_ []per.CompletePadding `asn1:"-" json:"-"`
}

// SegmentationInfoR15 represents the ASN.1 type SegmentationInfo-r15 (SEQUENCE).
type SegmentationInfoR15 struct {
	SegmentationOptionR15          int64                 `asn1:"tag:0,context,implicit"`
	AssistanceDataSegmentTypeR15   int64                 `asn1:"tag:1,context,implicit"`
	AssistanceDataSegmentNumberR15 int64                 `asn1:"tag:2,context,implicit"`
	ExtCount_                      int64                 `asn1:"-" json:"-"`
	ExtPresent_                    []bool                `asn1:"-" json:"-"`
	ExtData_                       [][]byte              `asn1:"-" json:"-"`
	PERPadding_                    per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_                 []per.CompletePadding `asn1:"-" json:"-"`
}

// OTDOAUEAssistedR15 represents the ASN.1 type OTDOA-UE-Assisted-r15 (SEQUENCE).
type OTDOAUEAssistedR15 struct {
	OtdoaReferenceCellInfoR15       OTDOAReferenceCellInfo     `asn1:"tag:0,context,implicit"`
	OtdoaNeighbourCellInfoR15       OTDOANeighbourCellInfoList `asn1:"tag:1,context,implicit"`
	OtdoaNeighbourCellInfoR15Indef_ bool                       `asn1:"-" json:"-"`
	ExtCount_                       int64                      `asn1:"-" json:"-"`
	ExtPresent_                     []bool                     `asn1:"-" json:"-"`
	ExtData_                        [][]byte                   `asn1:"-" json:"-"`
	PERPadding_                     per.FinalPadding           `asn1:"-" json:"-"`
	PERExtPadding_                  []per.CompletePadding      `asn1:"-" json:"-"`
}

// NRUEBTRPLocationDataR16 represents the ASN.1 type NR-UEB-TRP-LocationData-r16 (SEQUENCE).
type NRUEBTRPLocationDataR16 struct {
	NrTrpLocationInfoR16       NRTRPLocationInfoR16  `asn1:"tag:0,context,implicit"`
	NrTrpLocationInfoR16Indef_ bool                  `asn1:"-" json:"-"`
	NrDlPrsBeamInfoR16         NRDLPRSBeamInfoR16    `asn1:"tag:1,context,implicit,optional" json:"NrDlPrsBeamInfoR16,omitempty"`
	NrDlPrsBeamInfoR16Indef_   bool                  `asn1:"-" json:"-"`
	ExtCount_                  int64                 `asn1:"-" json:"-"`
	ExtPresent_                []bool                `asn1:"-" json:"-"`
	ExtData_                   [][]byte              `asn1:"-" json:"-"`
	PERPadding_                per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_             []per.CompletePadding `asn1:"-" json:"-"`
}

// NRUEBTRPRTDInfoR16 represents the ASN.1 type NR-UEB-TRP-RTD-Info-r16 (SEQUENCE).
type NRUEBTRPRTDInfoR16 struct {
	NrRtdInfoR16   NRRTDInfoR16          `asn1:"tag:0,context,implicit"`
	ExtCount_      int64                 `asn1:"-" json:"-"`
	ExtPresent_    []bool                `asn1:"-" json:"-"`
	ExtData_       [][]byte              `asn1:"-" json:"-"`
	PERPadding_    per.FinalPadding      `asn1:"-" json:"-"`
	PERExtPadding_ []per.CompletePadding `asn1:"-" json:"-"`
}

// NRIntegrityParametersR18 represents the ASN.1 type NR-IntegrityParameters-r18 (SEQUENCE).
type NRIntegrityParametersR18 struct {
	NrIntegrityParametersTRPLocationInfoR18    *NRIntegrityParametersTRPLocationInfoR18    `asn1:"tag:0,context,implicit,optional" json:"NrIntegrityParametersTRPLocationInfoR18,omitempty"`
	NrIntegrityParametersDLPRSBeamInfoR18      *NRIntegrityParametersDLPRSBeamInfoR18      `asn1:"tag:1,context,implicit,optional" json:"NrIntegrityParametersDLPRSBeamInfoR18,omitempty"`
	NrIntegrityParametersRTDInfoR18            *NRIntegrityParametersRTDInfoR18            `asn1:"tag:2,context,implicit,optional" json:"NrIntegrityParametersRTDInfoR18,omitempty"`
	NrIntegrityParametersTRPBeamAntennaInfoR18 *NRIntegrityParametersTRPBeamAntennaInfoR18 `asn1:"tag:3,context,implicit,optional" json:"NrIntegrityParametersTRPBeamAntennaInfoR18,omitempty"`
	ExtCount_                                  int64                                       `asn1:"-" json:"-"`
	ExtPresent_                                []bool                                      `asn1:"-" json:"-"`
	ExtData_                                   [][]byte                                    `asn1:"-" json:"-"`
	PERPadding_                                per.FinalPadding                            `asn1:"-" json:"-"`
	PERExtPadding_                             []per.CompletePadding                       `asn1:"-" json:"-"`
}

// MarshalUPER encodes AssistanceDataSIBelementR15 to UPER format.
func (v *AssistanceDataSIBelementR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *AssistanceDataSIBelementR15) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.ValueTagR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.ExpirationTimeR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.CipheringKeyDataR15 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.SegmentationInfoR15 != nil); err != nil {
		return err
	}
	if v.ValueTagR15 != nil {
		if err := per.EncodeInteger(bb, int64(*v.ValueTagR15), int64Ptr(0), int64Ptr(63), false); err != nil {
			return fmt.Errorf("encoding valueTag-r15: %w", err)
		}
	}
	if v.ExpirationTimeR15 != nil {
		if err := per.EncodeUTCTime(bb, *v.ExpirationTimeR15); err != nil {
			return fmt.Errorf("encoding expirationTime-r15: %w", err)
		}
	}
	if v.CipheringKeyDataR15 != nil {
		if err := v.CipheringKeyDataR15.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding cipheringKeyData-r15: %w", err)
		}
	}
	if v.SegmentationInfoR15 != nil {
		if err := v.SegmentationInfoR15.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding segmentationInfo-r15: %w", err)
		}
	}
	if err := per.EncodeOctetStringExt(bb, v.AssistanceDataElementR15, 0, 0, false, false); err != nil {
		return fmt.Errorf("encoding assistanceDataElement-r15: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern UPER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_uper.go:445
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLength(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern UPER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_uper.go:462
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern UPER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_uper.go:469
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenType(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes AssistanceDataSIBelementR15 from UPER format.
func (v *AssistanceDataSIBelementR15) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes AssistanceDataSIBelementR15 with explicit receiver options.
func (v *AssistanceDataSIBelementR15) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataSIBelementR15")
	}
	padding, err := per.CaptureFinalBits(bb, "AssistanceDataSIBelementR15")
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataSIBelementR15")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *AssistanceDataSIBelementR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = AssistanceDataSIBelementR15{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_valuetagr15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_expirationtimer15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_cipheringkeydatar15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_segmentationinfor15, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_valuetagr15 {
		val_valuetagr15, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(63), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ValueTagR15")
		}
		v.ValueTagR15 = &val_valuetagr15
	}
	if opt_expirationtimer15 {
		val_expirationtimer15, err := per.DecodeUTCTime(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExpirationTimeR15")
		}
		v.ExpirationTimeR15 = &val_expirationtimer15
	}
	if opt_cipheringkeydatar15 {
		var dec_cipheringkeydatar15 CipheringKeyDataR15
		if err := dec_cipheringkeydatar15.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "CipheringKeyDataR15")
		}
		v.CipheringKeyDataR15 = &dec_cipheringkeydatar15
	}
	if opt_segmentationinfor15 {
		var dec_segmentationinfor15 SegmentationInfoR15
		if err := dec_segmentationinfor15.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SegmentationInfoR15")
		}
		v.SegmentationInfoR15 = &dec_segmentationinfor15
	}
	val_assistancedataelementr15, err := per.DecodeOctetStringExt(bb, 0, 0, false, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataElementR15")
	}
	v.AssistanceDataElementR15 = val_assistancedataelementr15
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern UPER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_uper.go:643
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern UPER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_uper.go:646
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes CipheringKeyDataR15 to UPER format.
func (v *CipheringKeyDataR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *CipheringKeyDataR15) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeInteger(bb, int64(v.CipherSetIDR15), int64Ptr(0), int64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding cipherSetID-r15: %w", err)
	}
	if err := per.EncodeBitStringExt(bb, v.D0R15.Bytes, v.D0R15.BitLength, 1, 128, true, false); err != nil {
		return fmt.Errorf("encoding d0-r15: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern UPER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_uper.go:445
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLength(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern UPER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_uper.go:462
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern UPER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_uper.go:469
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenType(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes CipheringKeyDataR15 from UPER format.
func (v *CipheringKeyDataR15) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes CipheringKeyDataR15 with explicit receiver options.
func (v *CipheringKeyDataR15) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "CipheringKeyDataR15")
	}
	padding, err := per.CaptureFinalBits(bb, "CipheringKeyDataR15")
	if err != nil {
		return runtime.WrapDecodePath(err, "CipheringKeyDataR15")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *CipheringKeyDataR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = CipheringKeyDataR15{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_ciphersetidr15, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "CipherSetIDR15")
	}
	v.CipherSetIDR15 = val_ciphersetidr15
	bsBytes_d0r15, bsBitLen_d0r15, err := per.DecodeBitStringExt(bb, 1, 128, true, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "D0R15")
	}
	v.D0R15 = runtime.BitString{Bytes: bsBytes_d0r15, BitLength: bsBitLen_d0r15}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern UPER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_uper.go:643
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern UPER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_uper.go:646
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes SegmentationInfoR15 to UPER format.
func (v *SegmentationInfoR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *SegmentationInfoR15) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := per.EncodeEnumerated(bb, int64(v.SegmentationOptionR15), 2, false); err != nil {
		return fmt.Errorf("encoding segmentationOption-r15: %w", err)
	}
	if err := per.EncodeEnumerated(bb, int64(v.AssistanceDataSegmentTypeR15), 2, false); err != nil {
		return fmt.Errorf("encoding assistanceDataSegmentType-r15: %w", err)
	}
	if err := per.EncodeInteger(bb, int64(v.AssistanceDataSegmentNumberR15), int64Ptr(0), int64Ptr(63), false); err != nil {
		return fmt.Errorf("encoding assistanceDataSegmentNumber-r15: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern UPER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_uper.go:445
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLength(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern UPER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_uper.go:462
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern UPER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_uper.go:469
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenType(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes SegmentationInfoR15 from UPER format.
func (v *SegmentationInfoR15) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes SegmentationInfoR15 with explicit receiver options.
func (v *SegmentationInfoR15) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SegmentationInfoR15")
	}
	padding, err := per.CaptureFinalBits(bb, "SegmentationInfoR15")
	if err != nil {
		return runtime.WrapDecodePath(err, "SegmentationInfoR15")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *SegmentationInfoR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = SegmentationInfoR15{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_segmentationoptionr15, err := per.DecodeEnumerated(bb, 2, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SegmentationOptionR15")
	}
	v.SegmentationOptionR15 = val_segmentationoptionr15
	val_assistancedatasegmenttyper15, err := per.DecodeEnumerated(bb, 2, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataSegmentTypeR15")
	}
	v.AssistanceDataSegmentTypeR15 = val_assistancedatasegmenttyper15
	val_assistancedatasegmentnumberr15, err := per.DecodeInteger(bb, int64Ptr(0), int64Ptr(63), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataSegmentNumberR15")
	}
	v.AssistanceDataSegmentNumberR15 = val_assistancedatasegmentnumberr15
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern UPER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_uper.go:643
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern UPER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_uper.go:646
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes OTDOAUEAssistedR15 to UPER format.
func (v *OTDOAUEAssistedR15) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *OTDOAUEAssistedR15) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := v.OtdoaReferenceCellInfoR15.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding otdoa-ReferenceCellInfo-r15: %w", err)
	}
	if err := per.EncodeCollection(bb, int64(len(v.OtdoaNeighbourCellInfoR15)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 3, HasUpper: true}, false, func(fragmentOffset_otdoaneighbourcellinfor15, fragmentLength_otdoaneighbourcellinfor15 int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_otdoaneighbourcellinfor15 < 0 || fragmentOffset_otdoaneighbourcellinfor15 > int64(len(v.OtdoaNeighbourCellInfoR15)) || fragmentLength_otdoaneighbourcellinfor15 < 0 || fragmentLength_otdoaneighbourcellinfor15 > int64(len(v.OtdoaNeighbourCellInfoR15[fragmentOffset_otdoaneighbourcellinfor15:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, outerElem := range v.OtdoaNeighbourCellInfoR15[fragmentOffset_otdoaneighbourcellinfor15 : fragmentOffset_otdoaneighbourcellinfor15+fragmentLength_otdoaneighbourcellinfor15] {
			if err := MarshalUPEROTDOANeighbourFreqInfoTo(outerElem, bb); err != nil {
				return fmt.Errorf("encoding otdoa-NeighbourCellInfo-r15 element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding otdoa-NeighbourCellInfo-r15: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern UPER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_uper.go:445
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLength(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern UPER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_uper.go:462
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern UPER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_uper.go:469
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenType(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes OTDOAUEAssistedR15 from UPER format.
func (v *OTDOAUEAssistedR15) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes OTDOAUEAssistedR15 with explicit receiver options.
func (v *OTDOAUEAssistedR15) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAUEAssistedR15")
	}
	padding, err := per.CaptureFinalBits(bb, "OTDOAUEAssistedR15")
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAUEAssistedR15")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *OTDOAUEAssistedR15) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = OTDOAUEAssistedR15{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.OtdoaReferenceCellInfoR15.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OtdoaReferenceCellInfoR15")
	}
	v.OtdoaNeighbourCellInfoR15 = make(OTDOANeighbourCellInfoList, 0)
	_, errCollection_otdoaneighbourcellinfor15 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 3, HasUpper: true}, false, func(fragmentOffset_otdoaneighbourcellinfor15, fragmentLength_otdoaneighbourcellinfor15 int64) error {
		// arithmetic pattern UPER_FRAGMENT_LOOP_4: nonnegative fragment offset and length fit host int; gen/codegen_uper.go:1244
		if fragmentOffset_otdoaneighbourcellinfor15 < 0 || fragmentLength_otdoaneighbourcellinfor15 < 0 || fragmentLength_otdoaneighbourcellinfor15 > int64(^uint(0)>>1) || fragmentOffset_otdoaneighbourcellinfor15 > int64(^uint(0)>>1)-fragmentLength_otdoaneighbourcellinfor15 {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i_otdoaneighbourcellinfor15 := int64(0); i_otdoaneighbourcellinfor15 < fragmentLength_otdoaneighbourcellinfor15; i_otdoaneighbourcellinfor15++ {
			elem, err := UnmarshalUPEROTDOANeighbourFreqInfoFrom(bb)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("OtdoaNeighbourCellInfoR15[%d]", fragmentOffset_otdoaneighbourcellinfor15+i_otdoaneighbourcellinfor15))
			}
			v.OtdoaNeighbourCellInfoR15 = append(v.OtdoaNeighbourCellInfoR15, elem)
		}
		return nil
	})
	if errCollection_otdoaneighbourcellinfor15 != nil {
		return runtime.WrapDecodePath(errCollection_otdoaneighbourcellinfor15, "OtdoaNeighbourCellInfoR15")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern UPER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_uper.go:643
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern UPER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_uper.go:646
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes NRUEBTRPLocationDataR16 to UPER format.
func (v *NRUEBTRPLocationDataR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *NRUEBTRPLocationDataR16) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NrDlPrsBeamInfoR16 != nil); err != nil {
		return err
	}
	if err := per.EncodeCollection(bb, int64(len(v.NrTrpLocationInfoR16)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_nrtrplocationinfor16, fragmentLength_nrtrplocationinfor16 int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_nrtrplocationinfor16 < 0 || fragmentOffset_nrtrplocationinfor16 > int64(len(v.NrTrpLocationInfoR16)) || fragmentLength_nrtrplocationinfor16 < 0 || fragmentLength_nrtrplocationinfor16 > int64(len(v.NrTrpLocationInfoR16[fragmentOffset_nrtrplocationinfor16:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.NrTrpLocationInfoR16[fragmentOffset_nrtrplocationinfor16 : fragmentOffset_nrtrplocationinfor16+fragmentLength_nrtrplocationinfor16] {
			if err := elem.MarshalUPERTo(bb); err != nil {
				return fmt.Errorf("encoding nr-trp-LocationInfo-r16 element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding nr-trp-LocationInfo-r16: %w", err)
	}
	if v.NrDlPrsBeamInfoR16 != nil {
		if err := per.EncodeCollection(bb, int64(len(v.NrDlPrsBeamInfoR16)), per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_nrdlprsbeaminfor16, fragmentLength_nrdlprsbeaminfor16 int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_nrdlprsbeaminfor16 < 0 || fragmentOffset_nrdlprsbeaminfor16 > int64(len(v.NrDlPrsBeamInfoR16)) || fragmentLength_nrdlprsbeaminfor16 < 0 || fragmentLength_nrdlprsbeaminfor16 > int64(len(v.NrDlPrsBeamInfoR16[fragmentOffset_nrdlprsbeaminfor16:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, outerElem := range v.NrDlPrsBeamInfoR16[fragmentOffset_nrdlprsbeaminfor16 : fragmentOffset_nrdlprsbeaminfor16+fragmentLength_nrdlprsbeaminfor16] {
				if err := MarshalUPERNRDLPRSBeamInfoPerFreqLayerR16To(outerElem, bb); err != nil {
					return fmt.Errorf("encoding nr-dl-prs-BeamInfo-r16 element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding nr-dl-prs-BeamInfo-r16: %w", err)
		}
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern UPER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_uper.go:445
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLength(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern UPER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_uper.go:462
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern UPER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_uper.go:469
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenType(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes NRUEBTRPLocationDataR16 from UPER format.
func (v *NRUEBTRPLocationDataR16) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes NRUEBTRPLocationDataR16 with explicit receiver options.
func (v *NRUEBTRPLocationDataR16) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NRUEBTRPLocationDataR16")
	}
	padding, err := per.CaptureFinalBits(bb, "NRUEBTRPLocationDataR16")
	if err != nil {
		return runtime.WrapDecodePath(err, "NRUEBTRPLocationDataR16")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *NRUEBTRPLocationDataR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = NRUEBTRPLocationDataR16{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nrdlprsbeaminfor16, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.NrTrpLocationInfoR16 = make(NRTRPLocationInfoR16, 0)
	_, errCollection_nrtrplocationinfor16 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_nrtrplocationinfor16, fragmentLength_nrtrplocationinfor16 int64) error {
		// arithmetic pattern UPER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_uper.go:1188
		if fragmentOffset_nrtrplocationinfor16 < 0 || fragmentLength_nrtrplocationinfor16 < 0 || fragmentLength_nrtrplocationinfor16 > int64(^uint(0)>>1) || fragmentOffset_nrtrplocationinfor16 > int64(^uint(0)>>1)-fragmentLength_nrtrplocationinfor16 {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_nrtrplocationinfor16; i++ {
			var elem NRTRPLocationInfoPerFreqLayerR16
			if err := elem.UnmarshalUPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("NrTrpLocationInfoR16[%d]", fragmentOffset_nrtrplocationinfor16+i))
			}
			v.NrTrpLocationInfoR16 = append(v.NrTrpLocationInfoR16, elem)
		}
		return nil
	})
	if errCollection_nrtrplocationinfor16 != nil {
		return runtime.WrapDecodePath(errCollection_nrtrplocationinfor16, "NrTrpLocationInfoR16")
	}
	if opt_nrdlprsbeaminfor16 {
		tmp_nrdlprsbeaminfor16 := make(NRDLPRSBeamInfoR16, 0)
		_, errCollection_nrdlprsbeaminfor16 := per.DecodeCollection(bb, per.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, false, func(fragmentOffset_nrdlprsbeaminfor16, fragmentLength_nrdlprsbeaminfor16 int64) error {
			// arithmetic pattern UPER_FRAGMENT_LOOP_4: nonnegative fragment offset and length fit host int; gen/codegen_uper.go:1244
			if fragmentOffset_nrdlprsbeaminfor16 < 0 || fragmentLength_nrdlprsbeaminfor16 < 0 || fragmentLength_nrdlprsbeaminfor16 > int64(^uint(0)>>1) || fragmentOffset_nrdlprsbeaminfor16 > int64(^uint(0)>>1)-fragmentLength_nrdlprsbeaminfor16 {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i_nrdlprsbeaminfor16 := int64(0); i_nrdlprsbeaminfor16 < fragmentLength_nrdlprsbeaminfor16; i_nrdlprsbeaminfor16++ {
				elem, err := UnmarshalUPERNRDLPRSBeamInfoPerFreqLayerR16From(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("NrDlPrsBeamInfoR16[%d]", fragmentOffset_nrdlprsbeaminfor16+i_nrdlprsbeaminfor16))
				}
				tmp_nrdlprsbeaminfor16 = append(tmp_nrdlprsbeaminfor16, elem)
			}
			return nil
		})
		if errCollection_nrdlprsbeaminfor16 != nil {
			return runtime.WrapDecodePath(errCollection_nrdlprsbeaminfor16, "NrDlPrsBeamInfoR16")
		}
		v.NrDlPrsBeamInfoR16 = tmp_nrdlprsbeaminfor16
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern UPER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_uper.go:643
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern UPER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_uper.go:646
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes NRUEBTRPRTDInfoR16 to UPER format.
func (v *NRUEBTRPRTDInfoR16) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *NRUEBTRPRTDInfoR16) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := v.NrRtdInfoR16.MarshalUPERTo(bb); err != nil {
		return fmt.Errorf("encoding nr-rtd-Info-r16: %w", err)
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern UPER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_uper.go:445
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLength(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern UPER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_uper.go:462
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern UPER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_uper.go:469
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenType(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes NRUEBTRPRTDInfoR16 from UPER format.
func (v *NRUEBTRPRTDInfoR16) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes NRUEBTRPRTDInfoR16 with explicit receiver options.
func (v *NRUEBTRPRTDInfoR16) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NRUEBTRPRTDInfoR16")
	}
	padding, err := per.CaptureFinalBits(bb, "NRUEBTRPRTDInfoR16")
	if err != nil {
		return runtime.WrapDecodePath(err, "NRUEBTRPRTDInfoR16")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *NRUEBTRPRTDInfoR16) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = NRUEBTRPRTDInfoR16{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := v.NrRtdInfoR16.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NrRtdInfoR16")
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern UPER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_uper.go:643
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern UPER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_uper.go:646
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}

// MarshalUPER encodes NRIntegrityParametersR18 to UPER format.
func (v *NRIntegrityParametersR18) MarshalUPER() ([]byte, error) {
	bb := per.NewBitBuffer()
	if err := v.MarshalUPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.PERPadding_)
}

func (v *NRIntegrityParametersR18) MarshalUPERTo(bb *per.BitBuffer) error {
	hasExtensions := v.ExtCount_ > 0 || len(v.ExtData_) > 0
	if err := per.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := per.EncodeBoolean(bb, v.NrIntegrityParametersTRPLocationInfoR18 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NrIntegrityParametersDLPRSBeamInfoR18 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NrIntegrityParametersRTDInfoR18 != nil); err != nil {
		return err
	}
	if err := per.EncodeBoolean(bb, v.NrIntegrityParametersTRPBeamAntennaInfoR18 != nil); err != nil {
		return err
	}
	if v.NrIntegrityParametersTRPLocationInfoR18 != nil {
		if err := v.NrIntegrityParametersTRPLocationInfoR18.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nr-IntegrityParametersTRP-LocationInfo-r18: %w", err)
		}
	}
	if v.NrIntegrityParametersDLPRSBeamInfoR18 != nil {
		if err := v.NrIntegrityParametersDLPRSBeamInfoR18.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nr-IntegrityParametersDL-PRS-BeamInfo-r18: %w", err)
		}
	}
	if v.NrIntegrityParametersRTDInfoR18 != nil {
		if err := v.NrIntegrityParametersRTDInfoR18.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nr-IntegrityParametersRTD-Info-r18: %w", err)
		}
	}
	if v.NrIntegrityParametersTRPBeamAntennaInfoR18 != nil {
		if err := v.NrIntegrityParametersTRPBeamAntennaInfoR18.MarshalUPERTo(bb); err != nil {
			return fmt.Errorf("encoding nr-IntegrityParametersTRP-BeamAntennaInfo-r18: %w", err)
		}
	}
	if hasExtensions {
		extCount := v.ExtCount_
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern UPER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_uper.go:445
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", per.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := per.EncodeNormallySmallLength(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern UPER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_uper.go:462
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil)
			if err := per.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern UPER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_uper.go:469
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.ExtPresent_)) && v.ExtPresent_[i]) || (i < int64(len(v.ExtData_)) && v.ExtData_[i] != nil) {
				var data []byte
				if i < int64(len(v.ExtData_)) {
					data = v.ExtData_[i]
				}
				if err := per.EncodeOpenType(bb, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// UnmarshalUPER decodes NRIntegrityParametersR18 from UPER format.
func (v *NRIntegrityParametersR18) UnmarshalUPER(data []byte) error {
	return v.UnmarshalUPERWithOptions(data, per.DecodeOptions{})
}

// UnmarshalUPERWithOptions decodes NRIntegrityParametersR18 with explicit receiver options.
func (v *NRIntegrityParametersR18) UnmarshalUPERWithOptions(data []byte, options per.DecodeOptions) error {
	bb := per.NewBitBufferFromBytes(data)
	bb.SetDecodeOptions(options)
	if err := v.UnmarshalUPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NRIntegrityParametersR18")
	}
	padding, err := per.CaptureFinalBits(bb, "NRIntegrityParametersR18")
	if err != nil {
		return runtime.WrapDecodePath(err, "NRIntegrityParametersR18")
	}
	v.PERPadding_ = padding
	return nil
}

func (v *NRIntegrityParametersR18) UnmarshalUPERFrom(bb *per.BitBuffer) error {
	*v = NRIntegrityParametersR18{}
	hasExtensions, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nrintegrityparameterstrplocationinfor18, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_nrintegrityparametersdlprsbeaminfor18, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_nrintegrityparametersrtdinfor18, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_nrintegrityparameterstrpbeamantennainfor18, err := per.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_nrintegrityparameterstrplocationinfor18 {
		var dec_nrintegrityparameterstrplocationinfor18 NRIntegrityParametersTRPLocationInfoR18
		if err := dec_nrintegrityparameterstrplocationinfor18.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NrIntegrityParametersTRPLocationInfoR18")
		}
		v.NrIntegrityParametersTRPLocationInfoR18 = &dec_nrintegrityparameterstrplocationinfor18
	}
	if opt_nrintegrityparametersdlprsbeaminfor18 {
		var dec_nrintegrityparametersdlprsbeaminfor18 NRIntegrityParametersDLPRSBeamInfoR18
		if err := dec_nrintegrityparametersdlprsbeaminfor18.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NrIntegrityParametersDLPRSBeamInfoR18")
		}
		v.NrIntegrityParametersDLPRSBeamInfoR18 = &dec_nrintegrityparametersdlprsbeaminfor18
	}
	if opt_nrintegrityparametersrtdinfor18 {
		var dec_nrintegrityparametersrtdinfor18 NRIntegrityParametersRTDInfoR18
		if err := dec_nrintegrityparametersrtdinfor18.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NrIntegrityParametersRTDInfoR18")
		}
		v.NrIntegrityParametersRTDInfoR18 = &dec_nrintegrityparametersrtdinfor18
	}
	if opt_nrintegrityparameterstrpbeamantennainfor18 {
		var dec_nrintegrityparameterstrpbeamantennainfor18 NRIntegrityParametersTRPBeamAntennaInfoR18
		if err := dec_nrintegrityparameterstrpbeamantennainfor18.UnmarshalUPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NrIntegrityParametersTRPBeamAntennaInfoR18")
		}
		v.NrIntegrityParametersTRPBeamAntennaInfoR18 = &dec_nrintegrityparameterstrpbeamantennainfor18
	}
	if hasExtensions {
		extCount, extPresent, err := per.DecodeExtensionBitmap(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.ExtCount_ = extCount
		// arithmetic pattern UPER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_uper.go:643
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		v.ExtData_ = make([][]byte, extCount+1)
		v.ExtPresent_ = extPresent
		// arithmetic pattern UPER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_uper.go:646
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				data, err := per.DecodeOpenType(bb)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				v.ExtData_[i] = data
			}
		}
	}
	return nil
}
