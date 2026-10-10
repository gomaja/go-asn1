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

	// MaxNumOfPrivateExtensions5 is the integer constant for maxNumOfPrivateExtensions.
	MaxNumOfPrivateExtensions5 int64 = 10
)

// ExtensionContainer5 represents the ASN.1 type ExtensionContainer (SEQUENCE).
type ExtensionContainer5 struct {
	PrivateExtensionList       *PrivateExtensionList5 `asn1:"tag:0,context,implicit,optional" json:"PrivateExtensionList,omitempty"`
	PrivateExtensionListIndef_ bool                   `asn1:"-" json:"-"`
	PcsExtensions              *PCSExtensions5        `asn1:"tag:1,context,implicit,optional" json:"PcsExtensions,omitempty"`
	ExtCount_                  int64                  `asn1:"-" json:"-"`
	ExtPresent_                []bool                 `asn1:"-" json:"-"`
	ExtData_                   [][]byte               `asn1:"-" json:"-"`
	berOriginal_               []byte                 `asn1:"-" json:"-"`
	berSnapshot_               []byte                 `asn1:"-" json:"-"`
}

// SLRArgExtensionContainer5 represents the ASN.1 type SLR-ArgExtensionContainer (SEQUENCE).
type SLRArgExtensionContainer5 struct {
	PrivateExtensionList       *PrivateExtensionList5 `asn1:"tag:0,context,implicit,optional" json:"PrivateExtensionList,omitempty"`
	PrivateExtensionListIndef_ bool                   `asn1:"-" json:"-"`
	SlrArgPCSExtensions        *SLRArgPCSExtensions5  `asn1:"tag:1,context,implicit,optional" json:"SlrArgPCSExtensions,omitempty"`
	ExtCount_                  int64                  `asn1:"-" json:"-"`
	ExtPresent_                []bool                 `asn1:"-" json:"-"`
	ExtData_                   [][]byte               `asn1:"-" json:"-"`
	berOriginal_               []byte                 `asn1:"-" json:"-"`
	berSnapshot_               []byte                 `asn1:"-" json:"-"`
}

// PrivateExtensionList5 represents the ASN.1 type PrivateExtensionList (SEQUENCE_OF).
type PrivateExtensionList5 struct {
	Values       []PrivateExtension5 `json:"Values"`
	berOriginal_ []byte              `json:"-"`
	berSnapshot_ []byte              `json:"-"`
}

// PrivateExtension5 represents the ASN.1 type PrivateExtension (SEQUENCE).
type PrivateExtension5 struct {
	ExtId        runtime.ObjectIdentifier `asn1:""`
	ExtType      *runtime.RawValue        `asn1:",optional" json:"ExtType,omitempty" asn1c:"raw-preserve"`
	berOriginal_ []byte                   `asn1:"-" json:"-"`
	berSnapshot_ []byte                   `asn1:"-" json:"-"`
}

// PCSExtensions5 represents the ASN.1 type PCS-Extensions (SEQUENCE).
type PCSExtensions5 struct {
	ExtCount_    int64    `asn1:"-" json:"-"`
	ExtPresent_  []bool   `asn1:"-" json:"-"`
	ExtData_     [][]byte `asn1:"-" json:"-"`
	berOriginal_ []byte   `asn1:"-" json:"-"`
	berSnapshot_ []byte   `asn1:"-" json:"-"`
}

// SLRArgPCSExtensions5 represents the ASN.1 type SLR-Arg-PCS-Extensions (SEQUENCE).
type SLRArgPCSExtensions5 struct {
	NaESRKRequest *struct{} `asn1:"tag:0,context,implicit,optional" json:"NaESRKRequest,omitempty"`
	ExtCount_     int64     `asn1:"-" json:"-"`
	ExtPresent_   []bool    `asn1:"-" json:"-"`
	ExtData_      [][]byte  `asn1:"-" json:"-"`
	berOriginal_  []byte    `asn1:"-" json:"-"`
	berSnapshot_  []byte    `asn1:"-" json:"-"`
}

// MarshalBER encodes ExtensionContainer5 to BER format.
func (v *ExtensionContainer5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionContainer5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtensionContainer5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := ber.CheckEncodedLength(opts, "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalBERPrivateExtensionList5(v.PrivateExtensionList, ber.ChildEncodeOptions(opts, "privateExtensionList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding privateExtensionList: %w", err)
		}
		if v.PrivateExtensionListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_privateextensionlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_privateextensionlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding privateExtensionList: %w", encodeErr)
				}
			}
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
		enc_pcsextensions, err := v.PcsExtensions.MarshalBER(ber.ChildEncodeOptions(opts, "pcs-Extensions")...)
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
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ExtensionContainer5 to DER format.
func (v *ExtensionContainer5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionContainer5 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := ber.CheckEncodedLength(nil, "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalDERPrivateExtensionList5(v.PrivateExtensionList)
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
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtensionContainer5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensionContainer5 from BER/DER format.
func (v *ExtensionContainer5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtensionContainer5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtensionContainer5{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
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
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding ExtensionContainer5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionContainer5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateExtensionList
	v.PrivateExtensionListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_privateextensionlist, n_privateextensionlist, rawVal_privateextensionlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", err)
				}
				if decodedTag_privateextensionlist.Class != tag.ClassContextSpecific || decodedTag_privateextensionlist.Number != 0 || decodedTag_privateextensionlist.Constructed != true {
					return fmt.Errorf("decoding privateExtensionList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privateextensionlist)
				}
				reconstructed_privateextensionlist, reconstructionErr_privateextensionlist := ber.EncodeSequence(rawVal_privateextensionlist)
				if reconstructionErr_privateextensionlist != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", reconstructionErr_privateextensionlist)
				}
				dec_privateextensionlist, unmErr := UnmarshalBERPrivateExtensionList5(reconstructed_privateextensionlist, ber.ChildDecodeOptions(opts, "privateExtensionList")...)
				if unmErr != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", unmErr)
				}
				v.PrivateExtensionList = dec_privateextensionlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset > len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.PrivateExtensionListIndef_ = true
					}
				}
				if offset > len(content) || n_privateextensionlist < 0 || n_privateextensionlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privateextensionlist
				if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
					if constraintErr := ber.CheckDecodedLength(opts, "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode pcs-Extensions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_pcsextensions, n_pcsextensions, rawVal_pcsextensions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding pcs-Extensions: %w", err)
				}
				if decodedTag_pcsextensions.Class != tag.ClassContextSpecific || decodedTag_pcsextensions.Number != 1 || decodedTag_pcsextensions.Constructed != true {
					return fmt.Errorf("decoding pcs-Extensions: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pcsextensions)
				}
				reconstructed_pcsextensions, reconstructionErr_pcsextensions := ber.EncodeSequence(rawVal_pcsextensions)
				if reconstructionErr_pcsextensions != nil {
					return fmt.Errorf("decoding pcs-Extensions: %w", reconstructionErr_pcsextensions)
				}
				var dec_pcsextensions PCSExtensions5
				if unmErr := dec_pcsextensions.UnmarshalBER(reconstructed_pcsextensions, ber.ChildDecodeOptions(opts, "pcs-Extensions")...); unmErr != nil {
					return fmt.Errorf("decoding pcs-Extensions: %w", unmErr)
				}
				v.PcsExtensions = &dec_pcsextensions
				if offset < 0 || offset >
					len(content) || n_pcsextensions < 0 || n_pcsextensions > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_pcsextensions
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensionContainer5", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExtensionContainer5", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SLRArgExtensionContainer5 to BER format.
func (v *SLRArgExtensionContainer5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SLRArgExtensionContainer5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SLRArgExtensionContainer5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := ber.CheckEncodedLength(opts, "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalBERPrivateExtensionList5(v.PrivateExtensionList, ber.ChildEncodeOptions(opts, "privateExtensionList")...)
		if err != nil {
			return nil, fmt.Errorf("encoding privateExtensionList: %w", err)
		}
		if v.PrivateExtensionListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_privateextensionlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_privateextensionlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding privateExtensionList: %w", encodeErr)
				}
			}
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
		enc_slrargpcsextensions, err := v.SlrArgPCSExtensions.MarshalBER(ber.ChildEncodeOptions(opts, "slr-Arg-PCS-Extensions")...)
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
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SLRArgExtensionContainer5 to DER format.
func (v *SLRArgExtensionContainer5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SLRArgExtensionContainer5 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := ber.CheckEncodedLength(nil, "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalDERPrivateExtensionList5(v.PrivateExtensionList)
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
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SLRArgExtensionContainer5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SLRArgExtensionContainer5 from BER/DER format.
func (v *SLRArgExtensionContainer5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SLRArgExtensionContainer5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SLRArgExtensionContainer5{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
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
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SLRArgExtensionContainer5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SLRArgExtensionContainer5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateExtensionList
	v.PrivateExtensionListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_privateextensionlist, n_privateextensionlist, rawVal_privateextensionlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", err)
				}
				if decodedTag_privateextensionlist.Class != tag.ClassContextSpecific || decodedTag_privateextensionlist.Number != 0 || decodedTag_privateextensionlist.Constructed != true {
					return fmt.Errorf("decoding privateExtensionList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privateextensionlist)
				}
				reconstructed_privateextensionlist, reconstructionErr_privateextensionlist := ber.EncodeSequence(rawVal_privateextensionlist)
				if reconstructionErr_privateextensionlist != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", reconstructionErr_privateextensionlist)
				}
				dec_privateextensionlist, unmErr := UnmarshalBERPrivateExtensionList5(reconstructed_privateextensionlist, ber.ChildDecodeOptions(opts, "privateExtensionList")...)
				if unmErr != nil {
					return fmt.Errorf("decoding privateExtensionList: %w", unmErr)
				}
				v.PrivateExtensionList = dec_privateextensionlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset > len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.PrivateExtensionListIndef_ = true
					}
				}
				if offset > len(content) || n_privateextensionlist < 0 || n_privateextensionlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privateextensionlist
				if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
					if constraintErr := ber.CheckDecodedLength(opts, "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode slr-Arg-PCS-Extensions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_slrargpcsextensions, n_slrargpcsextensions, rawVal_slrargpcsextensions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding slr-Arg-PCS-Extensions: %w", err)
				}
				if decodedTag_slrargpcsextensions.Class != tag.ClassContextSpecific || decodedTag_slrargpcsextensions.Number != 1 || decodedTag_slrargpcsextensions.Constructed != true {
					return fmt.Errorf("decoding slr-Arg-PCS-Extensions: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_slrargpcsextensions)
				}
				reconstructed_slrargpcsextensions, reconstructionErr_slrargpcsextensions := ber.EncodeSequence(rawVal_slrargpcsextensions)
				if reconstructionErr_slrargpcsextensions != nil {
					return fmt.Errorf("decoding slr-Arg-PCS-Extensions: %w", reconstructionErr_slrargpcsextensions)
				}
				var dec_slrargpcsextensions SLRArgPCSExtensions5
				if unmErr := dec_slrargpcsextensions.UnmarshalBER(reconstructed_slrargpcsextensions, ber.ChildDecodeOptions(opts, "slr-Arg-PCS-Extensions")...); unmErr != nil {
					return fmt.Errorf("decoding slr-Arg-PCS-Extensions: %w", unmErr)
				}
				v.SlrArgPCSExtensions = &dec_slrargpcsextensions
				if offset < 0 || offset >
					len(content) || n_slrargpcsextensions < 0 || n_slrargpcsextensions >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_slrargpcsextensions
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SLRArgExtensionContainer5", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SLRArgExtensionContainer5", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERPrivateExtensionList5 encodes a PrivateExtensionList5 list to BER.
func MarshalBERPrivateExtensionList5(collection *PrivateExtensionList5, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERPrivateExtensionList5(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERPrivateExtensionList5(collection *PrivateExtensionList5, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedLength(opts, "PrivateExtensionList5", "SIZE (1..10)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERPrivateExtensionList5 encodes a PrivateExtensionList5 list to DER.
func MarshalDERPrivateExtensionList5(collection *PrivateExtensionList5) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedLength(nil, "PrivateExtensionList5", "SIZE (1..10)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PrivateExtensionList5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERPrivateExtensionList5 decodes a PrivateExtensionList5 list from BER.
func UnmarshalBERPrivateExtensionList5(data []byte, opts ...ber.DecodeOption) (returnValue *PrivateExtensionList5, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding PrivateExtensionList5: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PrivateExtensionList5", Cause: ber.ErrExtraData}
	}
	var result []PrivateExtension5
	offset := 0
	for offset < len(content) {
		elementData := content[offset:]
		var elem PrivateExtension5
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 10 {
		if constraintErr := ber.CheckDecodedLength(opts, "PrivateExtensionList5", "SIZE (1..10)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &PrivateExtensionList5{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERPrivateExtensionList5(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes PrivateExtension5 to BER format.
func (v *PrivateExtension5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PrivateExtension5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PrivateExtension5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PrivateExtension5 to DER format.
func (v *PrivateExtension5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrivateExtension5 receiver is nil", ber.ErrInvalidValue)
	}
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PrivateExtension5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrivateExtension5 from BER/DER format.
func (v *PrivateExtension5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PrivateExtension5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PrivateExtension5{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
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
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding PrivateExtension5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrivateExtension5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extId
	if offset >= len(content) {
		return fmt.Errorf("missing required field extId")
	}
	val_extid, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding extId: %w", err)
	}
	v.ExtId = runtime.ObjectIdentifier(val_extid)
	if offset > len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode extType
	if offset < len(content) {
		_, n_exttype, _, tlvErr_exttype := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_exttype != nil {
			return fmt.Errorf("decoding extType: %w", tlvErr_exttype)
		}
		if offset < 0 || offset >
			len(content) || n_exttype < 0 || n_exttype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_exttype := runtime.RawValue{Bytes: content[offset : offset+n_exttype]}
		v.ExtType = &tmp_exttype
		if offset < 0 || offset >
			len(content) || n_exttype < 0 || n_exttype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_exttype
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PrivateExtension5", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PCSExtensions5 to BER format.
func (v *PCSExtensions5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PCSExtensions5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PCSExtensions5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PCSExtensions5 to DER format.
func (v *PCSExtensions5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PCSExtensions5 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PCSExtensions5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PCSExtensions5 from BER/DER format.
func (v *PCSExtensions5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PCSExtensions5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PCSExtensions5{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
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
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding PCSExtensions5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PCSExtensions5", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PCSExtensions5", Cause: extErr_}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SLRArgPCSExtensions5 to BER format.
func (v *SLRArgPCSExtensions5) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SLRArgPCSExtensions5 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SLRArgPCSExtensions5) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
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
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SLRArgPCSExtensions5 to DER format.
func (v *SLRArgPCSExtensions5) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SLRArgPCSExtensions5 receiver is nil", ber.ErrInvalidValue)
	}
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
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SLRArgPCSExtensions5 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SLRArgPCSExtensions5 from BER/DER format.
func (v *SLRArgPCSExtensions5) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SLRArgPCSExtensions5 destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SLRArgPCSExtensions5{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
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
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding SLRArgPCSExtensions5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SLRArgPCSExtensions5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode na-ESRK-Request
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_naesrkrequest, n_naesrkrequest, rawVal_naesrkrequest, err := ber.DecodeTLV(content[offset:], opts...)
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
				if offset > len(content) || n_naesrkrequest < 0 || n_naesrkrequest > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_naesrkrequest
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SLRArgPCSExtensions5", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SLRArgPCSExtensions5", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(opts, fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		if offset < 0 || offset >
			len(content) || nExt_ < 0 || nExt_ > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
