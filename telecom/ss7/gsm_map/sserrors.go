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
	NewLmfRoutingId []byte   `asn1:"tag:0,context,explicit,optional" json:"NewLmfRoutingId,omitzero"`
	ExtCount_       int64    `asn1:"-" json:"-"`
	ExtPresent_     []bool   `asn1:"-" json:"-"`
	ExtData_        [][]byte `asn1:"-" json:"-"`
	berOriginal_    []byte   `asn1:"-" json:"-"`
	berSnapshot_    []byte   `asn1:"-" json:"-"`
}

// MarshalBER encodes PruAssociationRejParam to BER format.
func (v *PruAssociationRejParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PruAssociationRejParam receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PruAssociationRejParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.NewLmfRoutingId != nil {
		enc_newlmfroutingid, encodeErr_enc_newlmfroutingid := ber.EncodeOctetString(v.NewLmfRoutingId)
		if encodeErr_enc_newlmfroutingid != nil {
			return nil, fmt.Errorf("encoding newLmfRoutingId: %w", encodeErr_enc_newlmfroutingid)
		}
		{
			var encodeErr error
			enc_newlmfroutingid, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_newlmfroutingid)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding newLmfRoutingId: %w", encodeErr)
			}
		}
		children = append(children, enc_newlmfroutingid...)
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

// MarshalDER encodes PruAssociationRejParam to DER format.
func (v *PruAssociationRejParam) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PruAssociationRejParam receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.NewLmfRoutingId != nil {
		enc_newlmfroutingid, encodeErr_enc_newlmfroutingid := ber.EncodeOctetString(v.NewLmfRoutingId)
		if encodeErr_enc_newlmfroutingid != nil {
			return nil, fmt.Errorf("encoding newLmfRoutingId: %w", encodeErr_enc_newlmfroutingid)
		}
		{
			var encodeErr error
			enc_newlmfroutingid, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_newlmfroutingid)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding newLmfRoutingId: %w", encodeErr)
			}
		}
		children = append(children, enc_newlmfroutingid...)
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
		return nil, fmt.Errorf("encoding PruAssociationRejParam as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PruAssociationRejParam from BER/DER format.
func (v *PruAssociationRejParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PruAssociationRejParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PruAssociationRejParam{}
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
				decodedTag_newlmfroutingid, n_newlmfroutingid, innerData_newlmfroutingid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding newLmfRoutingId: %w", err)
				}
				if decodedTag_newlmfroutingid.Class != tag.ClassContextSpecific || decodedTag_newlmfroutingid.Number != 0 || decodedTag_newlmfroutingid.Constructed != true {
					return fmt.Errorf("decoding newLmfRoutingId: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newlmfroutingid)
				}
				_, innerUsed_newlmfroutingid, _, innerErr_newlmfroutingid := ber.DecodeTLV(innerData_newlmfroutingid, opts...)
				if innerErr_newlmfroutingid != nil {
					return fmt.Errorf("decoding newLmfRoutingId: %w", innerErr_newlmfroutingid)
				}
				if innerUsed_newlmfroutingid != len(innerData_newlmfroutingid) {
					return fmt.Errorf("decoding newLmfRoutingId: %w", ber.ErrExtraData)
				}
				// Decode inner value from explicit tag wrapper
				val_newlmfroutingid, _, err := ber.DecodeOctetString(innerData_newlmfroutingid, opts...)
				if err != nil {
					return fmt.Errorf("decoding newLmfRoutingId: %w", err)
				}
				tmp_newlmfroutingid := val_newlmfroutingid
				v.NewLmfRoutingId = tmp_newlmfroutingid
				if offset > len(content) || n_newlmfroutingid < 0 || n_newlmfroutingid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_newlmfroutingid
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PruAssociationRejParam", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if !ber.ConstraintToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "PruAssociationRejParam", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
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
