// Code generated from ASN.1 module "MAP-ExtensionDataTypes". DO NOT EDIT.

package gsm_map

import (
	"fmt"

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

const (

	// MaxNumOfPrivateExtensions is the integer constant for maxNumOfPrivateExtensions.
	MaxNumOfPrivateExtensions int64 = 10
)

// ExtensionContainer represents the ASN.1 type ExtensionContainer (SEQUENCE).
type ExtensionContainer struct {
	PrivateExtensionList          *PrivateExtensionList `asn1:"tag:0,context,implicit,optional" json:"PrivateExtensionList,omitempty"`
	berPrivateExtensionListIndef_ bool                  `asn1:"-" json:"-"`
	PcsExtensions                 *PCSExtensions        `asn1:"tag:1,context,implicit,optional" json:"PcsExtensions,omitempty"`
	ExtCount_                     int64                 `asn1:"-" json:"-"`
	ExtPresent_                   []bool                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SLRArgExtensionContainer represents the ASN.1 type SLR-ArgExtensionContainer (SEQUENCE).
type SLRArgExtensionContainer struct {
	PrivateExtensionList          *PrivateExtensionList `asn1:"tag:0,context,implicit,optional" json:"PrivateExtensionList,omitempty"`
	berPrivateExtensionListIndef_ bool                  `asn1:"-" json:"-"`
	SlrArgPCSExtensions           *SLRArgPCSExtensions  `asn1:"tag:1,context,implicit,optional" json:"SlrArgPCSExtensions,omitempty"`
	ExtCount_                     int64                 `asn1:"-" json:"-"`
	ExtPresent_                   []bool                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// PrivateExtensionList represents the ASN.1 type PrivateExtensionList (SEQUENCE_OF).
type PrivateExtensionList struct {
	Values         []PrivateExtension `json:"Values"`
	berReplayNode_ *ber.ReplayNode    `json:"-"`
}

// PrivateExtension represents the ASN.1 type PrivateExtension (SEQUENCE).
type PrivateExtension struct {
	ExtId runtime.ObjectIdentifier `asn1:""`
	// ExtType carries one complete foreign encoding. WithoutBERReplay and DER
	// copy elements passing generic DER checks; foreign schema rules need a typed binding.
	ExtType        *runtime.RawValue `asn1:",optional" json:"ExtType,omitempty" asn1c:"raw-preserve"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// PCSExtensions represents the ASN.1 type PCS-Extensions (SEQUENCE).
type PCSExtensions struct {
	ExtCount_   int64  `asn1:"-" json:"-"`
	ExtPresent_ []bool `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SLRArgPCSExtensions represents the ASN.1 type SLR-Arg-PCS-Extensions (SEQUENCE).
type SLRArgPCSExtensions struct {
	NaESRKRequest *struct{} `asn1:"tag:0,context,implicit,optional" json:"NaESRKRequest,omitempty"`
	ExtCount_     int64     `asn1:"-" json:"-"`
	ExtPresent_   []bool    `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes ExtensionContainer to BER format.
func (v *ExtensionContainer) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionContainer receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExtensionContainer).MarshalBER, (*ExtensionContainer).marshalBER, true)

}
func (v *ExtensionContainer) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := checkEncodedLength(opts, s6d1933_0, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalBERPrivateExtensionList(v.PrivateExtensionList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "privateExtensionList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "privateExtensionList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berPrivateExtensionListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_privateextensionlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_privateextensionlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "privateExtensionList", "encoding", false)
				}
			}
		} else {
			retagged_enc_privateextensionlist, tagErr_enc_privateextensionlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_privateextensionlist)
			if tagErr_enc_privateextensionlist != nil {
				return nil, qualifyBERError(tagErr_enc_privateextensionlist, "privateExtensionList", "encoding", false)
			}
			enc_privateextensionlist = retagged_enc_privateextensionlist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_privateextensionlist)
		children = append(children, enc_privateextensionlist...)
	}
	if v.PcsExtensions != nil {
		enc_pcsextensions, err := v.PcsExtensions.MarshalBER(ber.ChildEncodeOptions(opts, "pcs-Extensions")...)
		if err != nil {
			return nil, qualifyBERError(err, "pcs-Extensions", "encoding", false)
		}
		retagged_enc_pcsextensions, tagErr_enc_pcsextensions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_pcsextensions)
		if tagErr_enc_pcsextensions != nil {
			return nil, qualifyBERError(tagErr_enc_pcsextensions, "pcs-Extensions", "encoding", false)
		}
		enc_pcsextensions = retagged_enc_pcsextensions
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_pcsextensions)
		children = append(children, enc_pcsextensions...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s6d1933_0, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s6d1933_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ExtensionContainer) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ExtensionContainer to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExtensionContainer) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionContainer receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := checkEncodedLength(nil, s6d1933_0, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalDERPrivateExtensionList(v.PrivateExtensionList)
		if err != nil {
			return nil, qualifyBERError(err, "privateExtensionList", "encoding", true)
		}
		retagged_enc_privateextensionlist, tagErr_enc_privateextensionlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_privateextensionlist)
		if tagErr_enc_privateextensionlist != nil {
			return nil, qualifyBERError(tagErr_enc_privateextensionlist, "privateExtensionList", "encoding", true)
		}
		enc_privateextensionlist = retagged_enc_privateextensionlist
		children = append(children, enc_privateextensionlist...)
	}
	if v.PcsExtensions != nil {
		enc_pcsextensions, err := v.PcsExtensions.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "pcs-Extensions", "encoding", true)
		}
		retagged_enc_pcsextensions, tagErr_enc_pcsextensions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_pcsextensions)
		if tagErr_enc_pcsextensions != nil {
			return nil, qualifyBERError(tagErr_enc_pcsextensions, "pcs-Extensions", "encoding", true)
		}
		enc_pcsextensions = retagged_enc_pcsextensions
		children = append(children, enc_pcsextensions...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s6d1933_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s6d1933_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ExtensionContainer as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ExtensionContainer) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExtensionContainer from BER/DER format.
func (destination *ExtensionContainer) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExtensionContainer destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExtensionContainer)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6d1933_0, "child", (*ExtensionContainer).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExtensionContainer{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExtensionContainer).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ExtensionContainer SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionContainer", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateExtensionList
	v.berPrivateExtensionListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "privateExtensionList", content[offset:])
				decodedTag_privateextensionlist, n_privateextensionlist, rawVal_privateextensionlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "privateExtensionList", "decoding", false)
				}
				if decodedTag_privateextensionlist.Class != tag.ClassContextSpecific || decodedTag_privateextensionlist.Number != 0 || decodedTag_privateextensionlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privateextensionlist), "privateExtensionList", "decoding", false)
				}
				_ = rawVal_privateextensionlist
				if offset > len(content) || n_privateextensionlist < 0 || n_privateextensionlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_privateextensionlist, reconstructionErr_privateextensionlist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_privateextensionlist])
				if reconstructionErr_privateextensionlist != nil {
					return qualifyBERError(reconstructionErr_privateextensionlist, "privateExtensionList", "decoding", false)
				}
				dec_privateextensionlist, unmErr := UnmarshalBERPrivateExtensionList(reconstructed_privateextensionlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "privateExtensionList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "privateExtensionList", "decoding", false)
				}
				v.PrivateExtensionList = dec_privateextensionlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset > len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berPrivateExtensionListIndef_ = true
					}
				}
				if offset > len(content) || n_privateextensionlist < 0 || n_privateextensionlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privateextensionlist
				if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
					if constraintErr := checkDecodedLength(opts, s6d1933_0, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "pcs-Extensions", content[offset:])
				decodedTag_pcsextensions, n_pcsextensions, rawVal_pcsextensions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "pcs-Extensions", "decoding", false)
				}
				if decodedTag_pcsextensions.Class != tag.ClassContextSpecific || decodedTag_pcsextensions.Number != 1 || decodedTag_pcsextensions.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_pcsextensions), "pcs-Extensions", "decoding", false)
				}
				_ = rawVal_pcsextensions
				if offset < 0 || offset >
					len(content) || n_pcsextensions < 0 || n_pcsextensions > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_pcsextensions, reconstructionErr_pcsextensions := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_pcsextensions])
				if reconstructionErr_pcsextensions != nil {
					return qualifyBERError(reconstructionErr_pcsextensions, "pcs-Extensions", "decoding", false)
				}
				var dec_pcsextensions PCSExtensions
				if unmErr := dec_pcsextensions.UnmarshalBER(reconstructed_pcsextensions, ber.ChildDecodeOptions(opts, "pcs-Extensions")...); unmErr != nil {
					return qualifyBERError(unmErr, "pcs-Extensions", "decoding", false)
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensionContainer", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExtensionContainer", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s6d1933_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SLRArgExtensionContainer to BER format.
func (v *SLRArgExtensionContainer) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SLRArgExtensionContainer receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SLRArgExtensionContainer).MarshalBER, (*SLRArgExtensionContainer).marshalBER, true)

}
func (v *SLRArgExtensionContainer) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := checkEncodedLength(opts, s6d1933_1, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalBERPrivateExtensionList(v.PrivateExtensionList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "privateExtensionList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "privateExtensionList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berPrivateExtensionListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_privateextensionlist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_privateextensionlist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 0}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "privateExtensionList", "encoding", false)
				}
			}
		} else {
			retagged_enc_privateextensionlist, tagErr_enc_privateextensionlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_privateextensionlist)
			if tagErr_enc_privateextensionlist != nil {
				return nil, qualifyBERError(tagErr_enc_privateextensionlist, "privateExtensionList", "encoding", false)
			}
			enc_privateextensionlist = retagged_enc_privateextensionlist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_privateextensionlist)
		children = append(children, enc_privateextensionlist...)
	}
	if v.SlrArgPCSExtensions != nil {
		enc_slrargpcsextensions, err := v.SlrArgPCSExtensions.MarshalBER(ber.ChildEncodeOptions(opts, "slr-Arg-PCS-Extensions")...)
		if err != nil {
			return nil, qualifyBERError(err, "slr-Arg-PCS-Extensions", "encoding", false)
		}
		retagged_enc_slrargpcsextensions, tagErr_enc_slrargpcsextensions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_slrargpcsextensions)
		if tagErr_enc_slrargpcsextensions != nil {
			return nil, qualifyBERError(tagErr_enc_slrargpcsextensions, "slr-Arg-PCS-Extensions", "encoding", false)
		}
		enc_slrargpcsextensions = retagged_enc_slrargpcsextensions
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_slrargpcsextensions)
		children = append(children, enc_slrargpcsextensions...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s6d1933_1, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s6d1933_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SLRArgExtensionContainer) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SLRArgExtensionContainer to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SLRArgExtensionContainer) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SLRArgExtensionContainer receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := checkEncodedLength(nil, s6d1933_1, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalDERPrivateExtensionList(v.PrivateExtensionList)
		if err != nil {
			return nil, qualifyBERError(err, "privateExtensionList", "encoding", true)
		}
		retagged_enc_privateextensionlist, tagErr_enc_privateextensionlist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_privateextensionlist)
		if tagErr_enc_privateextensionlist != nil {
			return nil, qualifyBERError(tagErr_enc_privateextensionlist, "privateExtensionList", "encoding", true)
		}
		enc_privateextensionlist = retagged_enc_privateextensionlist
		children = append(children, enc_privateextensionlist...)
	}
	if v.SlrArgPCSExtensions != nil {
		enc_slrargpcsextensions, err := v.SlrArgPCSExtensions.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "slr-Arg-PCS-Extensions", "encoding", true)
		}
		retagged_enc_slrargpcsextensions, tagErr_enc_slrargpcsextensions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_slrargpcsextensions)
		if tagErr_enc_slrargpcsextensions != nil {
			return nil, qualifyBERError(tagErr_enc_slrargpcsextensions, "slr-Arg-PCS-Extensions", "encoding", true)
		}
		enc_slrargpcsextensions = retagged_enc_slrargpcsextensions
		children = append(children, enc_slrargpcsextensions...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s6d1933_1, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s6d1933_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SLRArgExtensionContainer as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SLRArgExtensionContainer) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SLRArgExtensionContainer from BER/DER format.
func (destination *SLRArgExtensionContainer) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SLRArgExtensionContainer destination is nil", ber.ErrInvalidValue)
	}
	v := new(SLRArgExtensionContainer)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6d1933_1, "child", (*SLRArgExtensionContainer).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SLRArgExtensionContainer{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SLRArgExtensionContainer).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SLRArgExtensionContainer SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SLRArgExtensionContainer", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateExtensionList
	v.berPrivateExtensionListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "privateExtensionList", content[offset:])
				decodedTag_privateextensionlist, n_privateextensionlist, rawVal_privateextensionlist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "privateExtensionList", "decoding", false)
				}
				if decodedTag_privateextensionlist.Class != tag.ClassContextSpecific || decodedTag_privateextensionlist.Number != 0 || decodedTag_privateextensionlist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privateextensionlist), "privateExtensionList", "decoding", false)
				}
				_ = rawVal_privateextensionlist
				if offset > len(content) || n_privateextensionlist < 0 || n_privateextensionlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_privateextensionlist, reconstructionErr_privateextensionlist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_privateextensionlist])
				if reconstructionErr_privateextensionlist != nil {
					return qualifyBERError(reconstructionErr_privateextensionlist, "privateExtensionList", "decoding", false)
				}
				dec_privateextensionlist, unmErr := UnmarshalBERPrivateExtensionList(reconstructed_privateextensionlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "privateExtensionList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "privateExtensionList", "decoding", false)
				}
				v.PrivateExtensionList = dec_privateextensionlist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset > len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berPrivateExtensionListIndef_ = true
					}
				}
				if offset > len(content) || n_privateextensionlist < 0 || n_privateextensionlist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privateextensionlist
				if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
					if constraintErr := checkDecodedLength(opts, s6d1933_1, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "slr-Arg-PCS-Extensions", content[offset:])
				decodedTag_slrargpcsextensions, n_slrargpcsextensions, rawVal_slrargpcsextensions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "slr-Arg-PCS-Extensions", "decoding", false)
				}
				if decodedTag_slrargpcsextensions.Class != tag.ClassContextSpecific || decodedTag_slrargpcsextensions.Number != 1 || decodedTag_slrargpcsextensions.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_slrargpcsextensions), "slr-Arg-PCS-Extensions", "decoding", false)
				}
				_ = rawVal_slrargpcsextensions
				if offset < 0 || offset >
					len(content) || n_slrargpcsextensions < 0 || n_slrargpcsextensions >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_slrargpcsextensions, reconstructionErr_slrargpcsextensions := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_slrargpcsextensions])
				if reconstructionErr_slrargpcsextensions != nil {
					return qualifyBERError(reconstructionErr_slrargpcsextensions, "slr-Arg-PCS-Extensions", "decoding", false)
				}
				var dec_slrargpcsextensions SLRArgPCSExtensions
				if unmErr := dec_slrargpcsextensions.UnmarshalBER(reconstructed_slrargpcsextensions, ber.ChildDecodeOptions(opts, "slr-Arg-PCS-Extensions")...); unmErr != nil {
					return qualifyBERError(unmErr, "slr-Arg-PCS-Extensions", "decoding", false)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SLRArgExtensionContainer", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SLRArgExtensionContainer", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s6d1933_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBERPrivateExtensionList encodes a PrivateExtensionList list to BER.
func MarshalBERPrivateExtensionList(collection *PrivateExtensionList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERPrivateExtensionList, marshalBERPrivateExtensionList, true)

}
func marshalBERPrivateExtensionList(collection *PrivateExtensionList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-ExtensionDataTypes.marshalBERPrivateExtensionList", "51.5", "PrivateExtensionList", "SIZE (1..10)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
		ber.RecordGeneratedBERChildPlacement(opts, len(children)-len(enc), enc)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearPrivateExtensionList(encoder *ber.LinearEncoder, collection *PrivateExtensionList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERPrivateExtensionList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERPrivateExtensionList encodes a PrivateExtensionList list to DER.
func MarshalDERPrivateExtensionList(collection *PrivateExtensionList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-ExtensionDataTypes.PrivateExtensionList", "51.5", "PrivateExtensionList", "SIZE (1..10)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PrivateExtensionList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearPrivateExtensionList(encoder *ber.LinearEncoder, collection *PrivateExtensionList) ([]byte, error) {
	encoded, err := MarshalDERPrivateExtensionList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERPrivateExtensionList decodes a PrivateExtensionList list from BER.
func UnmarshalBERPrivateExtensionList(data []byte, opts ...ber.DecodeOption) (returnValue *PrivateExtensionList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-ExtensionDataTypes.PrivateExtensionList", "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERPrivateExtensionList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding PrivateExtensionList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PrivateExtensionList", Cause: ber.ErrExtraData}
	}
	var result []PrivateExtension
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem PrivateExtension
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeIndexOptions(opts, len(result))...); unmErr != nil {
			return nil, qualifyBERError(unmErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 10 {
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-ExtensionDataTypes.PrivateExtensionList", "51.5", "PrivateExtensionList", "SIZE (1..10)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &PrivateExtensionList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERPrivateExtensionList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes PrivateExtension to BER format.
func (v *PrivateExtension) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PrivateExtension receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PrivateExtension).MarshalBER, (*PrivateExtension).marshalBER, true)

}
func (v *PrivateExtension) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_extid, oidErr := ber.EncodeObjectIdentifierChecked(v.ExtId)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "extId", "encoding", false)
	}
	children = append(children, enc_extid...)
	if v.ExtType != nil {
		if rawErr := ber.ValidateRawValueIdentifier(*v.ExtType); rawErr != nil {
			return nil, qualifyBERError(rawErr, "extType", "encoding", false)
		}
		enc_exttype := v.ExtType.Bytes
		if err := checkOpaqueElement(enc_exttype, opts, "extType", -1, "MAP-ExtensionDataTypes.PrivateExtension.extType", nil); err != nil {
			return nil, qualifyBERError(err, "extType", "encoding", false)
		}
		children = append(children, enc_exttype...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PrivateExtension) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PrivateExtension to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PrivateExtension) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrivateExtension receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_extid, oidErr := ber.EncodeObjectIdentifierChecked(v.ExtId)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "extId", "encoding", true)
	}
	children = append(children, enc_extid...)
	if v.ExtType != nil {
		if rawErr := ber.ValidateRawValueIdentifier(*v.ExtType); rawErr != nil {
			return nil, qualifyBERError(rawErr, "extType", "encoding", true)
		}
		enc_exttype := v.ExtType.Bytes
		if rawErr := ber.ValidateDEREncodedElement(enc_exttype); rawErr != nil {
			return nil, invalidDEROpaqueElement(enc_exttype, "extType", "MAP-ExtensionDataTypes.PrivateExtension.extType")
		}
		children = append(children, enc_exttype...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PrivateExtension as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PrivateExtension) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PrivateExtension from BER/DER format.
func (destination *PrivateExtension) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PrivateExtension destination is nil", ber.ErrInvalidValue)
	}
	v := new(PrivateExtension)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "MAP-ExtensionDataTypes.PrivateExtension", "child", (*PrivateExtension).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PrivateExtension{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PrivateExtension).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PrivateExtension SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrivateExtension", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extId
	if offset >= len(content) {
		return fmt.Errorf("missing required field extId")
	}
	{
		ber.MarkPreflightTarget(opts, "extId", content[offset:])
		val_extid, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "extId", "decoding", false)
		}
		v.ExtId = val_extid
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	// Decode extType
	if offset < len(content) {
		ber.MarkPreflightTarget(opts, "extType", content[offset:])
		rawTag_exttype, n_exttype, _, tlvErr_exttype := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_exttype != nil {
			return qualifyBERError(tlvErr_exttype, "extType", "decoding", false)
		}
		ber.MarkPreflightOpaque(opts, "extType", content[offset:], n_exttype)
		if offset < 0 || offset >
			len(content) || n_exttype < 0 || n_exttype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tmp_exttype := runtime.RawValue{Class: int(rawTag_exttype.Class), Tag: rawTag_exttype.Number, Constructed: rawTag_exttype.Constructed, Bytes: append([]byte(nil), content[offset:offset+n_exttype]...)}
		v.ExtType = &tmp_exttype
		if offset < 0 || offset >
			len(content) || n_exttype < 0 || n_exttype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_exttype
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PrivateExtension", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes PCSExtensions to BER format.
func (v *PCSExtensions) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PCSExtensions receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PCSExtensions).MarshalBER, (*PCSExtensions).marshalBER, true)

}
func (v *PCSExtensions) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, "MAP-ExtensionDataTypes.PCS-Extensions", children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PCSExtensions) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PCSExtensions to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PCSExtensions) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PCSExtensions receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, "MAP-ExtensionDataTypes.PCS-Extensions", children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PCSExtensions as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PCSExtensions) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PCSExtensions from BER/DER format.
func (destination *PCSExtensions) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PCSExtensions destination is nil", ber.ErrInvalidValue)
	}
	v := new(PCSExtensions)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "MAP-ExtensionDataTypes.PCS-Extensions", "child", (*PCSExtensions).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PCSExtensions{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PCSExtensions).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PCSExtensions SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PCSExtensions", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PCSExtensions", Cause: extErr_}
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

// MarshalBER encodes SLRArgPCSExtensions to BER format.
func (v *SLRArgPCSExtensions) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SLRArgPCSExtensions receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SLRArgPCSExtensions).MarshalBER, (*SLRArgPCSExtensions).marshalBER, true)

}
func (v *SLRArgPCSExtensions) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.NaESRKRequest != nil {
		enc_naesrkrequest := ber.EncodeNull()
		retagged_enc_naesrkrequest, tagErr_enc_naesrkrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naesrkrequest)
		if tagErr_enc_naesrkrequest != nil {
			return nil, qualifyBERError(tagErr_enc_naesrkrequest, "na-ESRK-Request", "encoding", false)
		}
		enc_naesrkrequest = retagged_enc_naesrkrequest
		children = append(children, enc_naesrkrequest...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s6d1933_2, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s6d1933_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SLRArgPCSExtensions) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SLRArgPCSExtensions to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SLRArgPCSExtensions) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SLRArgPCSExtensions receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.NaESRKRequest != nil {
		enc_naesrkrequest := ber.EncodeNull()
		retagged_enc_naesrkrequest, tagErr_enc_naesrkrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_naesrkrequest)
		if tagErr_enc_naesrkrequest != nil {
			return nil, qualifyBERError(tagErr_enc_naesrkrequest, "na-ESRK-Request", "encoding", true)
		}
		enc_naesrkrequest = retagged_enc_naesrkrequest
		children = append(children, enc_naesrkrequest...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s6d1933_2, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s6d1933_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SLRArgPCSExtensions as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SLRArgPCSExtensions) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SLRArgPCSExtensions from BER/DER format.
func (destination *SLRArgPCSExtensions) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SLRArgPCSExtensions destination is nil", ber.ErrInvalidValue)
	}
	v := new(SLRArgPCSExtensions)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s6d1933_2, "child", (*SLRArgPCSExtensions).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SLRArgPCSExtensions{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SLRArgPCSExtensions).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SLRArgPCSExtensions SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "na-ESRK-Request", content[offset:])
				decodedTag_naesrkrequest, n_naesrkrequest, rawVal_naesrkrequest, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "na-ESRK-Request", "decoding", false)
				}
				if decodedTag_naesrkrequest.Class != tag.ClassContextSpecific || decodedTag_naesrkrequest.Number != 0 || decodedTag_naesrkrequest.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_naesrkrequest), "na-ESRK-Request", "decoding", false)
				}
				if len(rawVal_naesrkrequest) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_naesrkrequest)), "na-ESRK-Request", "decoding", false)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SLRArgPCSExtensions", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SLRArgPCSExtensions", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s6d1933_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

const (
	s6d1933_0 = "MAP-ExtensionDataTypes.ExtensionContainer"
	s6d1933_1 = "MAP-ExtensionDataTypes.SLR-ArgExtensionContainer"
	s6d1933_2 = "MAP-ExtensionDataTypes.SLR-Arg-PCS-Extensions"
)
