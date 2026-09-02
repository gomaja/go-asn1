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

	// MaxNumOfPrivateExtensions3 is the integer constant for MaxNumOfPrivateExtensions3.
	MaxNumOfPrivateExtensions3 int64 = 10
)

// ExtensionContainer3 represents the ASN.1 type ExtensionContainer (SEQUENCE).
type ExtensionContainer3 struct {
	PrivateExtensionList       PrivateExtensionList3 `asn1:"tag:0,context,implicit,optional" json:"PrivateExtensionList,omitempty"`
	PrivateExtensionListIndef_ bool                  `asn1:"-" json:"-"`
	PcsExtensions              *PCSExtensions3       `asn1:"tag:1,context,implicit,optional" json:"PcsExtensions,omitempty"`
	ExtCount_                  int64                 `asn1:"-" json:"-"`
	ExtPresent_                []bool                `asn1:"-" json:"-"`
	ExtData_                   [][]byte              `asn1:"-" json:"-"`
}

// SLRArgExtensionContainer3 represents the ASN.1 type SLR-ArgExtensionContainer (SEQUENCE).
type SLRArgExtensionContainer3 struct {
	PrivateExtensionList       PrivateExtensionList3 `asn1:"tag:0,context,implicit,optional" json:"PrivateExtensionList,omitempty"`
	PrivateExtensionListIndef_ bool                  `asn1:"-" json:"-"`
	SlrArgPCSExtensions        *SLRArgPCSExtensions3 `asn1:"tag:1,context,implicit,optional" json:"SlrArgPCSExtensions,omitempty"`
	ExtCount_                  int64                 `asn1:"-" json:"-"`
	ExtPresent_                []bool                `asn1:"-" json:"-"`
	ExtData_                   [][]byte              `asn1:"-" json:"-"`
}

// PrivateExtensionList3 represents the ASN.1 type PrivateExtensionList (SEQUENCE_OF).
type PrivateExtensionList3 = []PrivateExtension3

// PrivateExtension3 represents the ASN.1 type PrivateExtension (SEQUENCE).
type PrivateExtension3 struct {
	ExtId   runtime.ObjectIdentifier `asn1:""`
	ExtType *runtime.RawValue        `asn1:",optional" json:"ExtType,omitempty" asn1c:"raw-preserve"`
}

// PCSExtensions3 represents the ASN.1 type PCS-Extensions (SEQUENCE).
type PCSExtensions3 struct {
	ExtCount_   int64    `asn1:"-" json:"-"`
	ExtPresent_ []bool   `asn1:"-" json:"-"`
	ExtData_    [][]byte `asn1:"-" json:"-"`
}

// SLRArgPCSExtensions3 represents the ASN.1 type SLR-Arg-PCS-Extensions (SEQUENCE).
type SLRArgPCSExtensions3 struct {
	NaESRKRequest *struct{} `asn1:"tag:0,context,implicit,optional" json:"NaESRKRequest,omitempty"`
	ExtCount_     int64     `asn1:"-" json:"-"`
	ExtPresent_   []bool    `asn1:"-" json:"-"`
	ExtData_      [][]byte  `asn1:"-" json:"-"`
}

// MarshalBER encodes ExtensionContainer3 to BER format.
func (v *ExtensionContainer3) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrivateExtensionList != nil {
		enc_privateextensionlist, err := MarshalBERPrivateExtensionList3(v.PrivateExtensionList)
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
			retagged_enc_privateextensionlist, tagErr_enc_privateextensionlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_privateextensionlist)
			if tagErr_enc_privateextensionlist != nil {
				return nil, fmt.Errorf("encoding privateExtensionList: %w", tagErr_enc_privateextensionlist)
			}
			enc_privateextensionlist = retagged_enc_privateextensionlist
		}
		children = append(children, enc_privateextensionlist...)
	}
	if v.PcsExtensions != nil {
		enc_pcsextensions, err := v.PcsExtensions.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding pcs-Extensions: %w", err)
		}
		retagged_enc_pcsextensions, tagErr_enc_pcsextensions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_pcsextensions)
		if tagErr_enc_pcsextensions != nil {
			return nil, fmt.Errorf("encoding pcs-Extensions: %w", tagErr_enc_pcsextensions)
		}
		enc_pcsextensions = retagged_enc_pcsextensions
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

// MarshalDER encodes ExtensionContainer3 to DER format.
func (v *ExtensionContainer3) MarshalDER() ([]byte, error) {
	var children []byte
	if v.PrivateExtensionList != nil {
		enc_privateextensionlist, err := MarshalDERPrivateExtensionList3(v.PrivateExtensionList)
		if err != nil {
			return nil, fmt.Errorf("encoding privateExtensionList: %w", err)
		}
		retagged_enc_privateextensionlist, tagErr_enc_privateextensionlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_privateextensionlist)
		if tagErr_enc_privateextensionlist != nil {
			return nil, fmt.Errorf("encoding privateExtensionList: %w", tagErr_enc_privateextensionlist)
		}
		enc_privateextensionlist = retagged_enc_privateextensionlist
		children = append(children, enc_privateextensionlist...)
	}
	if v.PcsExtensions != nil {
		enc_pcsextensions, err := v.PcsExtensions.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding pcs-Extensions: %w", err)
		}
		retagged_enc_pcsextensions, tagErr_enc_pcsextensions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_pcsextensions)
		if tagErr_enc_pcsextensions != nil {
			return nil, fmt.Errorf("encoding pcs-Extensions: %w", tagErr_enc_pcsextensions)
		}
		enc_pcsextensions = retagged_enc_pcsextensions
		children = append(children, enc_pcsextensions...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtensionContainer3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensionContainer3 from BER/DER format.
func (v *ExtensionContainer3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExtensionContainer3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionContainer3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateExtensionList
	v.PrivateExtensionListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_privateextensionlist, n_privateextensionlist, rawVal_privateextensionlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", err)
				}
				if decodedTag_privateextensionlist.Class != tag.ClassContextSpecific || decodedTag_privateextensionlist.Number != 0 || decodedTag_privateextensionlist.Constructed != true {
					return fmt.Errorf("decoding privateExtensionList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privateextensionlist)
				}
				reconstructed_privateextensionlist := ber.EncodeSequence(rawVal_privateextensionlist)
				dec_privateextensionlist, unmErr := UnmarshalBERPrivateExtensionList3(reconstructed_privateextensionlist)
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
				decodedTag_pcsextensions, n_pcsextensions, rawVal_pcsextensions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding pcs-Extensions: %w", err)
				}
				if decodedTag_pcsextensions.Class != tag.ClassContextSpecific || decodedTag_pcsextensions.Number != 1 || decodedTag_pcsextensions.Constructed != true {
					return fmt.Errorf("decoding pcs-Extensions: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pcsextensions)
				}
				reconstructed_pcsextensions := ber.EncodeSequence(rawVal_pcsextensions)
				var dec_pcsextensions PCSExtensions3
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensionContainer3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SLRArgExtensionContainer3 to BER format.
func (v *SLRArgExtensionContainer3) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrivateExtensionList != nil {
		enc_privateextensionlist, err := MarshalBERPrivateExtensionList3(v.PrivateExtensionList)
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
			retagged_enc_privateextensionlist, tagErr_enc_privateextensionlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_privateextensionlist)
			if tagErr_enc_privateextensionlist != nil {
				return nil, fmt.Errorf("encoding privateExtensionList: %w", tagErr_enc_privateextensionlist)
			}
			enc_privateextensionlist = retagged_enc_privateextensionlist
		}
		children = append(children, enc_privateextensionlist...)
	}
	if v.SlrArgPCSExtensions != nil {
		enc_slrargpcsextensions, err := v.SlrArgPCSExtensions.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding slr-Arg-PCS-Extensions: %w", err)
		}
		retagged_enc_slrargpcsextensions, tagErr_enc_slrargpcsextensions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_slrargpcsextensions)
		if tagErr_enc_slrargpcsextensions != nil {
			return nil, fmt.Errorf("encoding slr-Arg-PCS-Extensions: %w", tagErr_enc_slrargpcsextensions)
		}
		enc_slrargpcsextensions = retagged_enc_slrargpcsextensions
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

// MarshalDER encodes SLRArgExtensionContainer3 to DER format.
func (v *SLRArgExtensionContainer3) MarshalDER() ([]byte, error) {
	var children []byte
	if v.PrivateExtensionList != nil {
		enc_privateextensionlist, err := MarshalDERPrivateExtensionList3(v.PrivateExtensionList)
		if err != nil {
			return nil, fmt.Errorf("encoding privateExtensionList: %w", err)
		}
		retagged_enc_privateextensionlist, tagErr_enc_privateextensionlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_privateextensionlist)
		if tagErr_enc_privateextensionlist != nil {
			return nil, fmt.Errorf("encoding privateExtensionList: %w", tagErr_enc_privateextensionlist)
		}
		enc_privateextensionlist = retagged_enc_privateextensionlist
		children = append(children, enc_privateextensionlist...)
	}
	if v.SlrArgPCSExtensions != nil {
		enc_slrargpcsextensions, err := v.SlrArgPCSExtensions.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding slr-Arg-PCS-Extensions: %w", err)
		}
		retagged_enc_slrargpcsextensions, tagErr_enc_slrargpcsextensions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_slrargpcsextensions)
		if tagErr_enc_slrargpcsextensions != nil {
			return nil, fmt.Errorf("encoding slr-Arg-PCS-Extensions: %w", tagErr_enc_slrargpcsextensions)
		}
		enc_slrargpcsextensions = retagged_enc_slrargpcsextensions
		children = append(children, enc_slrargpcsextensions...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SLRArgExtensionContainer3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SLRArgExtensionContainer3 from BER/DER format.
func (v *SLRArgExtensionContainer3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SLRArgExtensionContainer3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SLRArgExtensionContainer3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateExtensionList
	v.PrivateExtensionListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_privateextensionlist, n_privateextensionlist, rawVal_privateextensionlist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", err)
				}
				if decodedTag_privateextensionlist.Class != tag.ClassContextSpecific || decodedTag_privateextensionlist.Number != 0 || decodedTag_privateextensionlist.Constructed != true {
					return fmt.Errorf("decoding privateExtensionList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privateextensionlist)
				}
				reconstructed_privateextensionlist := ber.EncodeSequence(rawVal_privateextensionlist)
				dec_privateextensionlist, unmErr := UnmarshalBERPrivateExtensionList3(reconstructed_privateextensionlist)
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
				decodedTag_slrargpcsextensions, n_slrargpcsextensions, rawVal_slrargpcsextensions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding slr-Arg-PCS-Extensions: %w", err)
				}
				if decodedTag_slrargpcsextensions.Class != tag.ClassContextSpecific || decodedTag_slrargpcsextensions.Number != 1 || decodedTag_slrargpcsextensions.Constructed != true {
					return fmt.Errorf("decoding slr-Arg-PCS-Extensions: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_slrargpcsextensions)
				}
				reconstructed_slrargpcsextensions := ber.EncodeSequence(rawVal_slrargpcsextensions)
				var dec_slrargpcsextensions SLRArgPCSExtensions3
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
			return &ber.DecodeError{Offset: offset, TypeName: "SLRArgExtensionContainer3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERPrivateExtensionList3 encodes a PrivateExtensionList3 list to BER.
func MarshalBERPrivateExtensionList3(list PrivateExtensionList3) ([]byte, error) {
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

// MarshalDERPrivateExtensionList3 encodes a PrivateExtensionList3 list to DER.
func MarshalDERPrivateExtensionList3(list PrivateExtensionList3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PrivateExtensionList3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERPrivateExtensionList3 decodes a PrivateExtensionList3 list from BER.
func UnmarshalBERPrivateExtensionList3(data []byte) (PrivateExtensionList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding PrivateExtensionList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PrivateExtensionList3", Cause: ber.ErrExtraData}
	}
	var result PrivateExtensionList3
	offset := 0
	for offset < len(content) {
		var elem PrivateExtension3
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

// MarshalBER encodes PrivateExtension3 to BER format.
func (v *PrivateExtension3) MarshalBER() ([]byte, error) {
	var children []byte
	enc_extid, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ExtId))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding extId: %w", oidErr)
	}
	children = append(children, enc_extid...)
	if v.ExtType != nil {
		enc_exttype := v.ExtType.Bytes
		children = append(children, enc_exttype...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PrivateExtension3 to DER format.
func (v *PrivateExtension3) MarshalDER() ([]byte, error) {
	var children []byte
	enc_extid, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ExtId))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding extId: %w", oidErr)
	}
	children = append(children, enc_extid...)
	if v.ExtType != nil {
		enc_exttype := v.ExtType.Bytes
		children = append(children, enc_exttype...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PrivateExtension3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrivateExtension3 from BER/DER format.
func (v *PrivateExtension3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PrivateExtension3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrivateExtension3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extId
	if offset >= len(content) {
		return fmt.Errorf("missing required field extId")
	}
	val_extid, n, err := ber.DecodeObjectIdentifier(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding extId: %w", err)
	}
	v.ExtId = runtime.ObjectIdentifier(val_extid)
	offset += n
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
		return &ber.DecodeError{Offset: offset, TypeName: "PrivateExtension3", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PCSExtensions3 to BER format.
func (v *PCSExtensions3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes PCSExtensions3 to DER format.
func (v *PCSExtensions3) MarshalDER() ([]byte, error) {
	var children []byte
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PCSExtensions3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PCSExtensions3 from BER/DER format.
func (v *PCSExtensions3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PCSExtensions3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PCSExtensions3", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PCSExtensions3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SLRArgPCSExtensions3 to BER format.
func (v *SLRArgPCSExtensions3) MarshalBER() ([]byte, error) {
	var children []byte
	if v.NaESRKRequest != nil {
		enc_naesrkrequest := ber.EncodeNull()
		retagged_enc_naesrkrequest, tagErr_enc_naesrkrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naesrkrequest)
		if tagErr_enc_naesrkrequest != nil {
			return nil, fmt.Errorf("encoding na-ESRK-Request: %w", tagErr_enc_naesrkrequest)
		}
		enc_naesrkrequest = retagged_enc_naesrkrequest
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

// MarshalDER encodes SLRArgPCSExtensions3 to DER format.
func (v *SLRArgPCSExtensions3) MarshalDER() ([]byte, error) {
	var children []byte
	if v.NaESRKRequest != nil {
		enc_naesrkrequest := ber.EncodeNull()
		retagged_enc_naesrkrequest, tagErr_enc_naesrkrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naesrkrequest)
		if tagErr_enc_naesrkrequest != nil {
			return nil, fmt.Errorf("encoding na-ESRK-Request: %w", tagErr_enc_naesrkrequest)
		}
		enc_naesrkrequest = retagged_enc_naesrkrequest
		children = append(children, enc_naesrkrequest...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SLRArgPCSExtensions3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SLRArgPCSExtensions3 from BER/DER format.
func (v *SLRArgPCSExtensions3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SLRArgPCSExtensions3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SLRArgPCSExtensions3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode na-ESRK-Request
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_naesrkrequest, n_naesrkrequest, rawVal_naesrkrequest, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding na-ESRK-Request: %w", err)
				}
				if decodedTag_naesrkrequest.Class != tag.ClassContextSpecific || decodedTag_naesrkrequest.Number != 0 || decodedTag_naesrkrequest.Constructed != false {
					return fmt.Errorf("decoding na-ESRK-Request: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrkrequest)
				}
				if len(rawVal_naesrkrequest) != 0 {
					return fmt.Errorf("decoding na-ESRK-Request: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_naesrkrequest))
				}
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
			return &ber.DecodeError{Offset: offset, TypeName: "SLRArgPCSExtensions3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
