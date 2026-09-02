// Code generated from ASN.1 module "SS-Errors". DO NOT EDIT.

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

// PruAssociationRejParam represents the ASN.1 type PruAssociationRejParam (SEQUENCE).
type PruAssociationRejParam struct {
	NewLmfRoutingId []byte   `asn1:"tag:0,context,explicit,optional" json:"NewLmfRoutingId,omitempty"`
	ExtCount_       int64    `asn1:"-" json:"-"`
	ExtPresent_     []bool   `asn1:"-" json:"-"`
	ExtData_        [][]byte `asn1:"-" json:"-"`
}

// MarshalBER encodes PruAssociationRejParam to BER format.
func (v *PruAssociationRejParam) MarshalBER() ([]byte, error) {
	var children []byte
	if v.NewLmfRoutingId != nil {
		enc_newlmfroutingid := ber.EncodeOctetString(v.NewLmfRoutingId)
		enc_newlmfroutingid = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_newlmfroutingid)
		children = append(children, enc_newlmfroutingid...)
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

// MarshalDER encodes PruAssociationRejParam to DER format.
func (v *PruAssociationRejParam) MarshalDER() ([]byte, error) {
	var children []byte
	if v.NewLmfRoutingId != nil {
		enc_newlmfroutingid := ber.EncodeOctetString(v.NewLmfRoutingId)
		enc_newlmfroutingid = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_newlmfroutingid)
		children = append(children, enc_newlmfroutingid...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded := ber.EncodeSequence(children)
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PruAssociationRejParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PruAssociationRejParam from BER/DER format.
func (v *PruAssociationRejParam) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PruAssociationRejParam SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PruAssociationRejParam", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode newLmfRoutingId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_newlmfroutingid, n_newlmfroutingid, innerData_newlmfroutingid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding newLmfRoutingId: %w", err)
				}
				if decodedTag_newlmfroutingid.Class != tag.ClassContextSpecific || decodedTag_newlmfroutingid.Number != 0 || decodedTag_newlmfroutingid.Constructed != true {
					return fmt.Errorf("decoding newLmfRoutingId: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newlmfroutingid)
				}
				// Decode inner value from explicit tag wrapper
				val_newlmfroutingid, _, err := ber.DecodeOctetString(innerData_newlmfroutingid)
				if err != nil {
					return fmt.Errorf("decoding newLmfRoutingId: %w", err)
				}
				tmp_newlmfroutingid := val_newlmfroutingid
				v.NewLmfRoutingId = tmp_newlmfroutingid
				offset += n_newlmfroutingid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PruAssociationRejParam", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
