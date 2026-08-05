// Code generated from ASN.1 module "MAP-ExtensionDataTypes". DO NOT EDIT.

package gsm_map

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

const (

	// MaxNumOfPrivateExtensions is the integer constant for maxNumOfPrivateExtensions.
	MaxNumOfPrivateExtensions int64 = 10
)

// ExtensionContainer represents the ASN.1 type ExtensionContainer (SEQUENCE).
type ExtensionContainer struct {
	PrivateExtensionList       PrivateExtensionList `asn1:"tag:0,context,implicit,optional" json:"PrivateExtensionList,omitempty"`
	PrivateExtensionListIndef_ bool                 `asn1:"-" json:"-"`
	PcsExtensions              *PCSExtensions       `asn1:"tag:1,context,implicit,optional" json:"PcsExtensions,omitempty"`
	ExtCount_                  int64                `asn1:"-" json:"-"`
	ExtPresent_                []bool               `asn1:"-" json:"-"`
	ExtData_                   [][]byte             `asn1:"-" json:"-"`
}

// SLRArgExtensionContainer represents the ASN.1 type SLR-ArgExtensionContainer (SEQUENCE).
type SLRArgExtensionContainer struct {
	PrivateExtensionList       PrivateExtensionList `asn1:"tag:0,context,implicit,optional" json:"PrivateExtensionList,omitempty"`
	PrivateExtensionListIndef_ bool                 `asn1:"-" json:"-"`
	SlrArgPCSExtensions        *SLRArgPCSExtensions `asn1:"tag:1,context,implicit,optional" json:"SlrArgPCSExtensions,omitempty"`
	ExtCount_                  int64                `asn1:"-" json:"-"`
	ExtPresent_                []bool               `asn1:"-" json:"-"`
	ExtData_                   [][]byte             `asn1:"-" json:"-"`
}

// PrivateExtensionList represents the ASN.1 type PrivateExtensionList (SEQUENCE_OF).
type PrivateExtensionList = []PrivateExtension

// PrivateExtension represents the ASN.1 type PrivateExtension (SEQUENCE).
type PrivateExtension struct {
	ExtId   runtime.RawValue  `asn1:""`
	ExtType *runtime.RawValue `asn1:",optional" json:"ExtType,omitempty"`
}

// PCSExtensions represents the ASN.1 type PCS-Extensions (SEQUENCE).
type PCSExtensions struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// SLRArgPCSExtensions represents the ASN.1 type SLR-Arg-PCS-Extensions (SEQUENCE).
type SLRArgPCSExtensions struct {
	NaESRKRequest *struct{} `asn1:"tag:0,context,implicit,optional" json:"NaESRKRequest,omitempty"`
	ExtCount_     int64     `asn1:"-" json:"-"`
	ExtPresent_   []bool    `asn1:"-" json:"-"`
	ExtData_      [][]byte  `asn1:"-" json:"-"`
}

// MarshalBER encodes ExtensionContainer to BER format.
func (v *ExtensionContainer) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrivateExtensionList != nil {
		enc_privateextensionlist, err := MarshalBERPrivateExtensionList(v.PrivateExtensionList)
		if err != nil {
			return nil, fmt.Errorf("encoding privateExtensionList: %w", err)
		}
		if v.PrivateExtensionListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_privateextensionlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_privateextensionlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
		} else {
			enc_privateextensionlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_privateextensionlist)
		}
		children = append(children, enc_privateextensionlist...)
	}
	if v.PcsExtensions != nil {
		enc_pcsextensions, err := v.PcsExtensions.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding pcs-Extensions: %w", err)
		}
		enc_pcsextensions = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_pcsextensions)
		children = append(children, enc_pcsextensions...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ExtensionContainer to DER format.
func (v *ExtensionContainer) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ExtensionContainer from BER/DER format.
func (v *ExtensionContainer) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExtensionContainer SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionContainer", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateExtensionList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_privateextensionlist, rawVal_privateextensionlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", err)
				}
				reconstructed_privateextensionlist := ber.EncodeSequence(rawVal_privateextensionlist)
				dec_privateextensionlist, unmErr := UnmarshalBERPrivateExtensionList(reconstructed_privateextensionlist)
				if unmErr != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", unmErr)
				}
				v.PrivateExtensionList = dec_privateextensionlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.PrivateExtensionListIndef_ = true
					}
				}
				offset += n_privateextensionlist
			}
		}
	}
	// Decode pcs-Extensions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_pcsextensions, rawVal_pcsextensions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pcs-Extensions: %w", err)
				}
				reconstructed_pcsextensions := ber.EncodeSequence(rawVal_pcsextensions)
				var dec_pcsextensions PCSExtensions
				if unmErr := dec_pcsextensions.UnmarshalBER(reconstructed_pcsextensions); unmErr != nil {
					return fmt.Errorf("decoding pcs-Extensions: %w", unmErr)
				}
				v.PcsExtensions = &dec_pcsextensions
				offset += n_pcsextensions
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensionContainer", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SLRArgExtensionContainer to BER format.
func (v *SLRArgExtensionContainer) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrivateExtensionList != nil {
		enc_privateextensionlist, err := MarshalBERPrivateExtensionList(v.PrivateExtensionList)
		if err != nil {
			return nil, fmt.Errorf("encoding privateExtensionList: %w", err)
		}
		if v.PrivateExtensionListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_privateextensionlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_privateextensionlist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
		} else {
			enc_privateextensionlist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_privateextensionlist)
		}
		children = append(children, enc_privateextensionlist...)
	}
	if v.SlrArgPCSExtensions != nil {
		enc_slrargpcsextensions, err := v.SlrArgPCSExtensions.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding slr-Arg-PCS-Extensions: %w", err)
		}
		enc_slrargpcsextensions = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_slrargpcsextensions)
		children = append(children, enc_slrargpcsextensions...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SLRArgExtensionContainer to DER format.
func (v *SLRArgExtensionContainer) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SLRArgExtensionContainer from BER/DER format.
func (v *SLRArgExtensionContainer) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SLRArgExtensionContainer SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SLRArgExtensionContainer", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateExtensionList
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_privateextensionlist, rawVal_privateextensionlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", err)
				}
				reconstructed_privateextensionlist := ber.EncodeSequence(rawVal_privateextensionlist)
				dec_privateextensionlist, unmErr := UnmarshalBERPrivateExtensionList(reconstructed_privateextensionlist)
				if unmErr != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", unmErr)
				}
				v.PrivateExtensionList = dec_privateextensionlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.PrivateExtensionListIndef_ = true
					}
				}
				offset += n_privateextensionlist
			}
		}
	}
	// Decode slr-Arg-PCS-Extensions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_slrargpcsextensions, rawVal_slrargpcsextensions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding slr-Arg-PCS-Extensions: %w", err)
				}
				reconstructed_slrargpcsextensions := ber.EncodeSequence(rawVal_slrargpcsextensions)
				var dec_slrargpcsextensions SLRArgPCSExtensions
				if unmErr := dec_slrargpcsextensions.UnmarshalBER(reconstructed_slrargpcsextensions); unmErr != nil {
					return fmt.Errorf("decoding slr-Arg-PCS-Extensions: %w", unmErr)
				}
				v.SlrArgPCSExtensions = &dec_slrargpcsextensions
				offset += n_slrargpcsextensions
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SLRArgExtensionContainer", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERPrivateExtensionList encodes a PrivateExtensionList list to BER.
func MarshalBERPrivateExtensionList(list PrivateExtensionList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERPrivateExtensionList decodes a PrivateExtensionList list from BER.
func UnmarshalBERPrivateExtensionList(data []byte) (PrivateExtensionList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding PrivateExtensionList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PrivateExtensionList", Cause: ber.ErrExtraData}
	}
	var result PrivateExtensionList
	offset := 0
	for offset < len(content) {
		var elem PrivateExtension
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes PrivateExtension to BER format.
func (v *PrivateExtension) MarshalBER() ([]byte, error) {
	var children []byte
	enc_extid := v.ExtId.Bytes
	children = append(children, enc_extid...)
	if v.ExtType != nil {
		enc_exttype := v.ExtType.Bytes
		children = append(children, enc_exttype...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PrivateExtension to DER format.
func (v *PrivateExtension) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PrivateExtension from BER/DER format.
func (v *PrivateExtension) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PrivateExtension SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrivateExtension", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extId
	if offset >= len(content) {
		return fmt.Errorf("missing required field extId")
	}
	_, n_extid, _, tlvErr_extid := ber.DecodeTLV(content[offset:])
	if tlvErr_extid != nil {
		return fmt.Errorf("decoding extId: %w", tlvErr_extid)
	}
	v.ExtId = runtime.RawValue{Bytes: content[offset : offset+n_extid]}
	offset += n_extid
	// Decode extType
	if offset < len(content) {
		_, n_exttype, _, tlvErr_exttype := ber.DecodeTLV(content[offset:])
		if tlvErr_exttype != nil {
			return fmt.Errorf("decoding extType: %w", tlvErr_exttype)
		}
		tmp_exttype := runtime.RawValue{Bytes: content[offset : offset+n_exttype]}
		v.ExtType = &tmp_exttype
		offset += n_exttype
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PrivateExtension", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PCSExtensions to BER format.
func (v *PCSExtensions) MarshalBER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PCSExtensions to DER format.
func (v *PCSExtensions) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PCSExtensions from BER/DER format.
func (v *PCSExtensions) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PCSExtensions SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PCSExtensions", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PCSExtensions", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SLRArgPCSExtensions to BER format.
func (v *SLRArgPCSExtensions) MarshalBER() ([]byte, error) {
	var children []byte
	if v.NaESRKRequest != nil {
		enc_naesrkrequest := ber.EncodeNull()
		enc_naesrkrequest = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_naesrkrequest)
		children = append(children, enc_naesrkrequest...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SLRArgPCSExtensions to DER format.
func (v *SLRArgPCSExtensions) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SLRArgPCSExtensions from BER/DER format.
func (v *SLRArgPCSExtensions) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SLRArgPCSExtensions SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SLRArgPCSExtensions", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode na-ESRK-Request
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_naesrkrequest, rawVal_naesrkrequest, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding na-ESRK-Request: %w", err)
				}
				_ = rawVal_naesrkrequest
				v.NaESRKRequest = &struct{}{}
				offset += n_naesrkrequest
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SLRArgPCSExtensions", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
