// Code generated from ASN.1 module "MAP-ExtensionDataTypes". DO NOT EDIT.

package v21_map_extensiondatatypes

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

	// ExtensionDataTypesMaxNumOfPrivateExtensions is the integer constant for maxNumOfPrivateExtensions.
	ExtensionDataTypesMaxNumOfPrivateExtensions int64 = 10
)

// ExtensionDataTypesExtensionContainer represents the ASN.1 type ExtensionContainer (SEQUENCE).
type ExtensionDataTypesExtensionContainer struct {
	PrivateExtensionList          *ExtensionDataTypesPrivateExtensionList `asn1:"tag:0,context,implicit,optional" json:"PrivateExtensionList,omitempty"`
	berPrivateExtensionListIndef_ bool                                    `asn1:"-" json:"-"`
	PcsExtensions                 *ExtensionDataTypesPCSExtensions        `asn1:"tag:1,context,implicit,optional" json:"PcsExtensions,omitempty"`
	ExtCount_                     int64                                   `asn1:"-" json:"-"`
	ExtPresent_                   []bool                                  `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ExtensionDataTypesSLRArgExtensionContainer represents the ASN.1 type SLR-ArgExtensionContainer (SEQUENCE).
type ExtensionDataTypesSLRArgExtensionContainer struct {
	PrivateExtensionList          *ExtensionDataTypesPrivateExtensionList `asn1:"tag:0,context,implicit,optional" json:"PrivateExtensionList,omitempty"`
	berPrivateExtensionListIndef_ bool                                    `asn1:"-" json:"-"`
	SlrArgPCSExtensions           *ExtensionDataTypesSLRArgPCSExtensions  `asn1:"tag:1,context,implicit,optional" json:"SlrArgPCSExtensions,omitempty"`
	ExtCount_                     int64                                   `asn1:"-" json:"-"`
	ExtPresent_                   []bool                                  `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ExtensionDataTypesPrivateExtensionList represents the ASN.1 type PrivateExtensionList (SEQUENCE_OF).
type ExtensionDataTypesPrivateExtensionList struct {
	Values         []ExtensionDataTypesPrivateExtension `json:"Values"`
	berReplayNode_ *ber.ReplayNode                      `json:"-"`
}

// ExtensionDataTypesPrivateExtension represents the ASN.1 type PrivateExtension (SEQUENCE).
type ExtensionDataTypesPrivateExtension struct {
	ExtId runtime.ObjectIdentifier `asn1:""`
	// ExtType carries one complete foreign encoding. WithoutBERReplay and DER
	// copy elements passing generic DER checks; foreign schema rules need a typed binding.
	ExtType        *runtime.RawValue `asn1:",optional" json:"ExtType,omitempty" asn1c:"raw-preserve"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// ExtensionDataTypesPCSExtensions represents the ASN.1 type PCS-Extensions (SEQUENCE).
type ExtensionDataTypesPCSExtensions struct {
	ExtCount_   int64  `asn1:"-" json:"-"`
	ExtPresent_ []bool `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ExtensionDataTypesSLRArgPCSExtensions represents the ASN.1 type SLR-Arg-PCS-Extensions (SEQUENCE).
type ExtensionDataTypesSLRArgPCSExtensions struct {
	NaESRKRequest *struct{} `asn1:"tag:0,context,implicit,optional" json:"NaESRKRequest,omitempty"`
	ExtCount_     int64     `asn1:"-" json:"-"`
	ExtPresent_   []bool    `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes ExtensionDataTypesExtensionContainer to BER format.
func (v *ExtensionDataTypesExtensionContainer) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionDataTypesExtensionContainer receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExtensionDataTypesExtensionContainer).MarshalBER, (*ExtensionDataTypesExtensionContainer).marshalBER, true)

}
func (v *ExtensionDataTypesExtensionContainer) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := checkEncodedLength(opts, s745c27_0, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalBERExtensionDataTypesPrivateExtensionList(v.PrivateExtensionList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "privateExtensionList"))...)
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
		if err := checkOpaqueAddition(ext, opts, s745c27_0, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s745c27_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ExtensionDataTypesExtensionContainer) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ExtensionDataTypesExtensionContainer to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExtensionDataTypesExtensionContainer) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionDataTypesExtensionContainer receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := checkEncodedLength(nil, s745c27_0, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalDERExtensionDataTypesPrivateExtensionList(v.PrivateExtensionList)
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
			return nil, invalidDERAddition(ext, s745c27_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s745c27_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ExtensionDataTypesExtensionContainer as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ExtensionDataTypesExtensionContainer) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExtensionDataTypesExtensionContainer from BER/DER format.
func (destination *ExtensionDataTypesExtensionContainer) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExtensionDataTypesExtensionContainer destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExtensionDataTypesExtensionContainer)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s745c27_0, "child", (*ExtensionDataTypesExtensionContainer).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExtensionDataTypesExtensionContainer{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExtensionDataTypesExtensionContainer).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ExtensionDataTypesExtensionContainer SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionDataTypesExtensionContainer", Cause: ber.ErrExtraData}
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
				dec_privateextensionlist, unmErr := UnmarshalBERExtensionDataTypesPrivateExtensionList(reconstructed_privateextensionlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "privateExtensionList"))...)
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
					if constraintErr := checkDecodedLength(opts, s745c27_0, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
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
				var dec_pcsextensions ExtensionDataTypesPCSExtensions
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensionDataTypesExtensionContainer", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExtensionDataTypesExtensionContainer", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s745c27_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ExtensionDataTypesSLRArgExtensionContainer to BER format.
func (v *ExtensionDataTypesSLRArgExtensionContainer) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionDataTypesSLRArgExtensionContainer receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExtensionDataTypesSLRArgExtensionContainer).MarshalBER, (*ExtensionDataTypesSLRArgExtensionContainer).marshalBER, true)

}
func (v *ExtensionDataTypesSLRArgExtensionContainer) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := checkEncodedLength(opts, s745c27_1, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalBERExtensionDataTypesPrivateExtensionList(v.PrivateExtensionList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "privateExtensionList"))...)
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
		if err := checkOpaqueAddition(ext, opts, s745c27_1, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s745c27_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ExtensionDataTypesSLRArgExtensionContainer) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ExtensionDataTypesSLRArgExtensionContainer to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExtensionDataTypesSLRArgExtensionContainer) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionDataTypesSLRArgExtensionContainer receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateExtensionList != nil {
		if len((v.PrivateExtensionList).Values) < 1 || len((v.PrivateExtensionList).Values) > 10 {
			if constraintErr := checkEncodedLength(nil, s745c27_1, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privateextensionlist, err := MarshalDERExtensionDataTypesPrivateExtensionList(v.PrivateExtensionList)
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
			return nil, invalidDERAddition(ext, s745c27_1, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s745c27_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ExtensionDataTypesSLRArgExtensionContainer as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ExtensionDataTypesSLRArgExtensionContainer) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExtensionDataTypesSLRArgExtensionContainer from BER/DER format.
func (destination *ExtensionDataTypesSLRArgExtensionContainer) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExtensionDataTypesSLRArgExtensionContainer destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExtensionDataTypesSLRArgExtensionContainer)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s745c27_1, "child", (*ExtensionDataTypesSLRArgExtensionContainer).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExtensionDataTypesSLRArgExtensionContainer{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExtensionDataTypesSLRArgExtensionContainer).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ExtensionDataTypesSLRArgExtensionContainer SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionDataTypesSLRArgExtensionContainer", Cause: ber.ErrExtraData}
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
				dec_privateextensionlist, unmErr := UnmarshalBERExtensionDataTypesPrivateExtensionList(reconstructed_privateextensionlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "privateExtensionList"))...)
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
					if constraintErr := checkDecodedLength(opts, s745c27_1, "51.5", "privateExtensionList", "SIZE (1..10)", len((v.PrivateExtensionList).Values)); constraintErr != nil {
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
					len(content) || n_slrargpcsextensions < 0 || n_slrargpcsextensions > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_slrargpcsextensions, reconstructionErr_slrargpcsextensions := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_slrargpcsextensions])
				if reconstructionErr_slrargpcsextensions != nil {
					return qualifyBERError(reconstructionErr_slrargpcsextensions, "slr-Arg-PCS-Extensions", "decoding", false)
				}
				var dec_slrargpcsextensions ExtensionDataTypesSLRArgPCSExtensions
				if unmErr := dec_slrargpcsextensions.UnmarshalBER(reconstructed_slrargpcsextensions, ber.ChildDecodeOptions(opts, "slr-Arg-PCS-Extensions")...); unmErr != nil {
					return qualifyBERError(unmErr, "slr-Arg-PCS-Extensions", "decoding", false)
				}
				v.SlrArgPCSExtensions = &dec_slrargpcsextensions
				if offset < 0 || offset >
					len(content) || n_slrargpcsextensions < 0 || n_slrargpcsextensions > len(content[offset:]) {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensionDataTypesSLRArgExtensionContainer", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExtensionDataTypesSLRArgExtensionContainer", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s745c27_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBERExtensionDataTypesPrivateExtensionList encodes a ExtensionDataTypesPrivateExtensionList list to BER.
func MarshalBERExtensionDataTypesPrivateExtensionList(collection *ExtensionDataTypesPrivateExtensionList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERExtensionDataTypesPrivateExtensionList, marshalBERExtensionDataTypesPrivateExtensionList, true)

}
func marshalBERExtensionDataTypesPrivateExtensionList(collection *ExtensionDataTypesPrivateExtensionList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-ExtensionDataTypes.marshalBERExtensionDataTypesPrivateExtensionList", "51.5", "PrivateExtensionList", "SIZE (1..10)", len(list)); constraintErr != nil {
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

func appendBERLinearExtensionDataTypesPrivateExtensionList(encoder *ber.LinearEncoder, collection *ExtensionDataTypesPrivateExtensionList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERExtensionDataTypesPrivateExtensionList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERExtensionDataTypesPrivateExtensionList encodes a ExtensionDataTypesPrivateExtensionList list to DER.
func MarshalDERExtensionDataTypesPrivateExtensionList(collection *ExtensionDataTypesPrivateExtensionList) ([]byte, error) {
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
		return nil, fmt.Errorf("%s: %w", "encoding ExtensionDataTypesPrivateExtensionList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearExtensionDataTypesPrivateExtensionList(encoder *ber.LinearEncoder, collection *ExtensionDataTypesPrivateExtensionList) ([]byte, error) {
	encoded, err := MarshalDERExtensionDataTypesPrivateExtensionList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERExtensionDataTypesPrivateExtensionList decodes a ExtensionDataTypesPrivateExtensionList list from BER.
func UnmarshalBERExtensionDataTypesPrivateExtensionList(data []byte, opts ...ber.DecodeOption) (returnValue *ExtensionDataTypesPrivateExtensionList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-ExtensionDataTypes.PrivateExtensionList", "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERExtensionDataTypesPrivateExtensionList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding ExtensionDataTypesPrivateExtensionList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ExtensionDataTypesPrivateExtensionList", Cause: ber.ErrExtraData}
	}
	var result []ExtensionDataTypesPrivateExtension
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem ExtensionDataTypesPrivateExtension
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
	decoded := &ExtensionDataTypesPrivateExtensionList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERExtensionDataTypesPrivateExtensionList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes ExtensionDataTypesPrivateExtension to BER format.
func (v *ExtensionDataTypesPrivateExtension) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionDataTypesPrivateExtension receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExtensionDataTypesPrivateExtension).MarshalBER, (*ExtensionDataTypesPrivateExtension).marshalBER, true)

}
func (v *ExtensionDataTypesPrivateExtension) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
func (v *ExtensionDataTypesPrivateExtension) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ExtensionDataTypesPrivateExtension to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExtensionDataTypesPrivateExtension) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionDataTypesPrivateExtension receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("%s: %w", "encoding ExtensionDataTypesPrivateExtension as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ExtensionDataTypesPrivateExtension) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExtensionDataTypesPrivateExtension from BER/DER format.
func (destination *ExtensionDataTypesPrivateExtension) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExtensionDataTypesPrivateExtension destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExtensionDataTypesPrivateExtension)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "MAP-ExtensionDataTypes.PrivateExtension", "child", (*ExtensionDataTypesPrivateExtension).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExtensionDataTypesPrivateExtension{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExtensionDataTypesPrivateExtension).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ExtensionDataTypesPrivateExtension SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionDataTypesPrivateExtension", Cause: ber.ErrExtraData}
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
		return &ber.DecodeError{Offset: offset, TypeName: "ExtensionDataTypesPrivateExtension", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ExtensionDataTypesPCSExtensions to BER format.
func (v *ExtensionDataTypesPCSExtensions) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionDataTypesPCSExtensions receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExtensionDataTypesPCSExtensions).MarshalBER, (*ExtensionDataTypesPCSExtensions).marshalBER, true)

}
func (v *ExtensionDataTypesPCSExtensions) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
func (v *ExtensionDataTypesPCSExtensions) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ExtensionDataTypesPCSExtensions to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExtensionDataTypesPCSExtensions) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionDataTypesPCSExtensions receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("%s: %w", "encoding ExtensionDataTypesPCSExtensions as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ExtensionDataTypesPCSExtensions) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExtensionDataTypesPCSExtensions from BER/DER format.
func (destination *ExtensionDataTypesPCSExtensions) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExtensionDataTypesPCSExtensions destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExtensionDataTypesPCSExtensions)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "MAP-ExtensionDataTypes.PCS-Extensions", "child", (*ExtensionDataTypesPCSExtensions).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExtensionDataTypesPCSExtensions{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExtensionDataTypesPCSExtensions).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ExtensionDataTypesPCSExtensions SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionDataTypesPCSExtensions", Cause: ber.ErrExtraData}
	}
	offset := 0
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensionDataTypesPCSExtensions", Cause: extErr_}
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

// MarshalBER encodes ExtensionDataTypesSLRArgPCSExtensions to BER format.
func (v *ExtensionDataTypesSLRArgPCSExtensions) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionDataTypesSLRArgPCSExtensions receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExtensionDataTypesSLRArgPCSExtensions).MarshalBER, (*ExtensionDataTypesSLRArgPCSExtensions).marshalBER, true)

}
func (v *ExtensionDataTypesSLRArgPCSExtensions) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		if err := checkOpaqueAddition(ext, opts, s745c27_2, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s745c27_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ExtensionDataTypesSLRArgPCSExtensions) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ExtensionDataTypesSLRArgPCSExtensions to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExtensionDataTypesSLRArgPCSExtensions) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionDataTypesSLRArgPCSExtensions receiver is nil", ber.ErrInvalidValue)
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
			return nil, invalidDERAddition(ext, s745c27_2, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s745c27_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ExtensionDataTypesSLRArgPCSExtensions as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ExtensionDataTypesSLRArgPCSExtensions) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExtensionDataTypesSLRArgPCSExtensions from BER/DER format.
func (destination *ExtensionDataTypesSLRArgPCSExtensions) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExtensionDataTypesSLRArgPCSExtensions destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExtensionDataTypesSLRArgPCSExtensions)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s745c27_2, "child", (*ExtensionDataTypesSLRArgPCSExtensions).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExtensionDataTypesSLRArgPCSExtensions{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExtensionDataTypesSLRArgPCSExtensions).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ExtensionDataTypesSLRArgPCSExtensions SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionDataTypesSLRArgPCSExtensions", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ExtensionDataTypesSLRArgPCSExtensions", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ExtensionDataTypesSLRArgPCSExtensions", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s745c27_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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
	s745c27_0 = "MAP-ExtensionDataTypes.ExtensionContainer"
	s745c27_1 = "MAP-ExtensionDataTypes.SLR-ArgExtensionContainer"
	s745c27_2 = "MAP-ExtensionDataTypes.SLR-Arg-PCS-Extensions"
)
