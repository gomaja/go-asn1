// Code generated from ASN.1 module "UnidialoguePDUs". DO NOT EDIT.

package tcap

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

// UniDialogueAsId returns the OID value for uniDialogue-as-id.
func UniDialogueAsId() runtime.ObjectIdentifier {
	return runtime.ObjectIdentifier{0, 0, 17, 773, 1, 2, 1}
}

// UniDialoguePDU choice constants.
const (
	UniDialoguePDUChoiceUnidialoguePDU = 1
)

// UniDialoguePDU represents the ASN.1 CHOICE type UniDialoguePDU.
type UniDialoguePDU struct {
	Choice         int
	berOriginal_   []byte    `json:"-"`
	berSnapshot_   []byte    `json:"-"`
	UnidialoguePDU *AUDTApdu `json:"UnidialoguePDU,omitempty"`
}

// NewUniDialoguePDUUnidialoguePDU creates a UniDialoguePDU with the unidialoguePDU alternative.
func NewUniDialoguePDUUnidialoguePDU(v AUDTApdu) UniDialoguePDU {
	return UniDialoguePDU{
		Choice:         UniDialoguePDUChoiceUnidialoguePDU,
		UnidialoguePDU: &v,
	}
}

// AUDTApdu represents the ASN.1 type AUDT-apdu (SEQUENCE).
type AUDTApdu struct {
	ProtocolVersion        *runtime.BitString       `asn1:"tag:0,context,implicit,optional" json:"ProtocolVersion,omitempty"`
	ApplicationContextName runtime.ObjectIdentifier `asn1:"tag:1,context,explicit"`
	UserInformation        *AUDTApduUserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_  bool                     `asn1:"-" json:"-"`
	berOriginal_           []byte                   `asn1:"-" json:"-"`
	berSnapshot_           []byte                   `asn1:"-" json:"-"`
}

// asn1c:raw-preserve
// AUDTApduUserInformation represents the ASN.1 type AUDT-apdu-user-information (SEQUENCE_OF).
type AUDTApduUserInformation struct {
	Values       []runtime.External `json:"Values"`
	berOriginal_ []byte             `json:"-"`
	berSnapshot_ []byte             `json:"-"`
}

// MarshalBER encodes UniDialoguePDU to BER format.
func (v *UniDialoguePDU) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UniDialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UniDialoguePDU) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case UniDialoguePDUChoiceUnidialoguePDU:
		if v.UnidialoguePDU == nil {
			return nil, fmt.Errorf("%w: choice UniDialoguePDU: unidialoguePDU is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.UnidialoguePDU.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding unidialoguePDU: %w", err)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding unidialoguePDU: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for UniDialoguePDU", v.Choice)
	}
}

// MarshalDER encodes UniDialoguePDU to DER format.
func (v *UniDialoguePDU) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UniDialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case UniDialoguePDUChoiceUnidialoguePDU:
		if v.UnidialoguePDU == nil {
			return nil, fmt.Errorf("%w: choice UniDialoguePDU: unidialoguePDU is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.UnidialoguePDU.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding unidialoguePDU: %w", err)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 0, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding unidialoguePDU: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding unidialoguePDU as DER: %w", derErr)
		}
		return enc_der_0, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UniDialoguePDU as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UniDialoguePDU from BER/DER format.
func (v *UniDialoguePDU) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UniDialoguePDU destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
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
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UniDialoguePDU{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for UniDialoguePDU CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for UniDialoguePDU: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding UniDialoguePDU CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "UniDialoguePDU", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = UniDialoguePDUChoiceUnidialoguePDU
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding unidialoguePDU: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 0, Constructed: true}, rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec AUDTApdu
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding unidialoguePDU: %w", unmErr)
		}
		v.UnidialoguePDU = &dec
	} else {
		return fmt.Errorf("unknown tag %s for UniDialoguePDU CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AUDTApdu to BER format.
func (v *AUDTApdu) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AUDTApdu receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AUDTApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ProtocolVersion != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "protocol-version", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:523
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, (8-(v.ProtocolVersion.BitLength%8))%8)
		if encodeErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", encodeErr_enc_protocolversion)
		}
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", tagErr_enc_protocolversion)
		}
		enc_protocolversion = retagged_enc_protocolversion
		children = append(children, enc_protocolversion...)
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ApplicationContextName))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding application-context-name: %w", oidErr)
	}
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding application-context-name: %w", encodeErr)
		}
	}
	children = append(children, enc_applicationcontextname...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERAUDTApduUserInformation(v.UserInformation, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding user-information: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 0, Constructed: true}, children)
}

// MarshalDER encodes AUDTApdu to DER format.
func (v *AUDTApdu) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AUDTApdu receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ProtocolVersion != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "protocol-version", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "protocol-version", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:523
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, (8-(v.ProtocolVersion.BitLength%8))%8)
		if encodeErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", encodeErr_enc_protocolversion)
		}
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, fmt.Errorf("encoding protocol-version: %w", tagErr_enc_protocolversion)
		}
		enc_protocolversion = retagged_enc_protocolversion
		children = append(children, enc_protocolversion...)
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked([]uint64(v.ApplicationContextName))
	if oidErr != nil {
		return nil, fmt.Errorf("encoding application-context-name: %w", oidErr)
	}
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, fmt.Errorf("encoding application-context-name: %w", encodeErr)
		}
	}
	children = append(children, enc_applicationcontextname...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalDERAUDTApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
		if tagErr_enc_userinformation != nil {
			return nil, fmt.Errorf("encoding user-information: %w", tagErr_enc_userinformation)
		}
		enc_userinformation = retagged_enc_userinformation
		children = append(children, enc_userinformation...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassApplication, 0, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding AUDTApdu: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AUDTApdu as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AUDTApdu from BER/DER format.
func (v *AUDTApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AUDTApdu destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AUDTApdu{}
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("decoding AUDTApdu: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AUDTApdu: %w: expected tag [APPLICATION 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AUDTApdu", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocol-version
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_protocolversion, n_protocolversion, rawVal_protocolversion, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding protocol-version: %w", err)
				}
				if decodedTag_protocolversion.Class != tag.ClassContextSpecific || decodedTag_protocolversion.Number != 0 {
					return fmt.Errorf("decoding protocol-version: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_protocolversion)
				}
				bsBytes_protocolversion, bsUnused_protocolversion, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_protocolversion.Constructed, rawVal_protocolversion, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding protocol-version: %w", bsErr)
				}
				bsBitLength_protocolversion, bsLenErr_protocolversion := ber.BitStringBitLength(len(bsBytes_protocolversion), bsUnused_protocolversion)
				if bsLenErr_protocolversion != nil {
					return fmt.Errorf("decoding protocol-version: %w", bsLenErr_protocolversion)
				}
				tmp_protocolversion := runtime.BitString{Bytes: bsBytes_protocolversion, BitLength: bsBitLength_protocolversion}
				v.ProtocolVersion = &tmp_protocolversion
				if offset < 0 || offset >
					len(content) || n_protocolversion < 0 || n_protocolversion >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_protocolversion
			}
		}
	}
	// Decode application-context-name
	if offset >= len(content) {
		return fmt.Errorf("missing required field application-context-name")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for application-context-name, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_applicationcontextname, n_applicationcontextname, innerData_applicationcontextname, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding application-context-name: %w", err)
	}
	if decodedTag_applicationcontextname.Class != tag.ClassContextSpecific || decodedTag_applicationcontextname.Number != 1 || decodedTag_applicationcontextname.Constructed != true {
		return fmt.Errorf("decoding application-context-name: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_applicationcontextname)
	}
	// Decode inner value from explicit tag wrapper
	val_applicationcontextname, _, oidErr := ber.DecodeObjectIdentifier(innerData_applicationcontextname, opts...)
	if oidErr != nil {
		return fmt.Errorf("decoding application-context-name: %w", oidErr)
	}
	v.ApplicationContextName = runtime.ObjectIdentifier(val_applicationcontextname)
	if offset < 0 || offset >
		len(content) || n_applicationcontextname < 0 || n_applicationcontextname >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_applicationcontextname
	// Decode user-information
	v.UserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return fmt.Errorf("decoding user-information: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation)
				}
				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeSequence(rawVal_userinformation)
				if reconstructionErr_userinformation != nil {
					return fmt.Errorf("decoding user-information: %w", reconstructionErr_userinformation)
				}
				dec_userinformation, unmErr := UnmarshalBERAUDTApduUserInformation(reconstructed_userinformation, ber.ChildDecodeOptions(opts, "user-information")...)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_userinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AUDTApdu", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERAUDTApduUserInformation encodes a AUDTApduUserInformation list to BER.
func MarshalBERAUDTApduUserInformation(collection *AUDTApduUserInformation, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERAUDTApduUserInformation(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERAUDTApduUserInformation(collection *AUDTApduUserInformation, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternal(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERAUDTApduUserInformation encodes a AUDTApduUserInformation list to DER.
func MarshalDERAUDTApduUserInformation(collection *AUDTApduUserInformation) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	var children []byte
	for _, elem := range list {
		encodedElem, extErr := ber.EncodeExternalDER(runtime.External(elem))
		if extErr != nil {
			return nil, fmt.Errorf("encoding element: %w", extErr)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AUDTApduUserInformation as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERAUDTApduUserInformation decodes a AUDTApduUserInformation list from BER.
func UnmarshalBERAUDTApduUserInformation(data []byte, opts ...ber.DecodeOption) (*AUDTApduUserInformation, error) {
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding AUDTApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AUDTApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result []runtime.External
	offset := 0
	for offset < len(content) {
		decodedElem, n, extErr := ber.DecodeExternal(content[offset:], opts...)
		if extErr != nil {
			return nil, fmt.Errorf("decoding element: %w", extErr)
		}
		result = append(result, decodedElem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	decoded := &AUDTApduUserInformation{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERAUDTApduUserInformation(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}
