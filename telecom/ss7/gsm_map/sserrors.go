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
	NewLmfRoutingId []byte          `asn1:"tag:0,context,explicit,optional" json:"NewLmfRoutingId,omitzero"`
	ExtCount_       int64           `asn1:"-" json:"-"`
	ExtPresent_     []bool          `asn1:"-" json:"-"`
	ExtData_        [][]byte        `asn1:"-" json:"-"`
	berReplayNode_  *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes PruAssociationRejParam to BER format.
func (v *PruAssociationRejParam) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PruAssociationRejParam receiver is nil", ber.ErrInvalidValue)
	}
	if v.berReplayNode_ == nil {
		return v.marshalBER(opts...)
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(v.berReplayNode_, opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(v.berReplayNode_, opts); ok {
		return replayBytes, nil
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, v.berReplayNode_, opts), nil
}
func (v *PruAssociationRejParam) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.NewLmfRoutingId != nil {
		enc_newlmfroutingid, encodeErr_enc_newlmfroutingid := ber.EncodeOctetString(v.NewLmfRoutingId)
		if encodeErr_enc_newlmfroutingid != nil {
			return nil, qualifyBERError(encodeErr_enc_newlmfroutingid, "newLmfRoutingId", "encoding", false)
		}
		{
			var encodeErr error
			enc_newlmfroutingid, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_newlmfroutingid)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "newLmfRoutingId", "encoding", false)
			}
		}
		children = append(children, enc_newlmfroutingid...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueReplay(opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
			if constraintErr := ber.CheckEncodedValue(opts, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PruAssociationRejParam) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
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
			return nil, qualifyBERError(encodeErr_enc_newlmfroutingid, "newLmfRoutingId", "encoding", true)
		}
		{
			var encodeErr error
			enc_newlmfroutingid, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 0, enc_newlmfroutingid)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "newLmfRoutingId", "encoding", true)
			}
		}
		children = append(children, enc_newlmfroutingid...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if constraintErr := ber.CheckEncodedValue(nil, "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding PruAssociationRejParam as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PruAssociationRejParam) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PruAssociationRejParam from BER/DER format.
func (v *PruAssociationRejParam) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PruAssociationRejParam destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe PruAssociationRejParam
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = PruAssociationRejParam{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *PruAssociationRejParam, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PruAssociationRejParam SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "newLmfRoutingId", content[offset:])
				decodedTag_newlmfroutingid, n_newlmfroutingid, innerData_newlmfroutingid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "newLmfRoutingId", "decoding", false)
				}
				if decodedTag_newlmfroutingid.Class != tag.ClassContextSpecific || decodedTag_newlmfroutingid.Number != 0 || decodedTag_newlmfroutingid.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_newlmfroutingid), "newLmfRoutingId", "decoding", false)
				}
				_, innerUsed_newlmfroutingid, _, innerErr_newlmfroutingid := ber.DecodeTLV(innerData_newlmfroutingid, opts...)
				if innerErr_newlmfroutingid != nil {
					return qualifyBERError(innerErr_newlmfroutingid, "newLmfRoutingId", "decoding", false)
				}
				if innerUsed_newlmfroutingid != len(innerData_newlmfroutingid) {
					return qualifyBERError(ber.ErrExtraData, "newLmfRoutingId", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "newLmfRoutingId", innerData_newlmfroutingid)
				val_newlmfroutingid, _, err := ber.DecodeOctetString(innerData_newlmfroutingid, opts...)
				if err != nil {
					return qualifyBERError(err, "newLmfRoutingId", "decoding", false)
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
