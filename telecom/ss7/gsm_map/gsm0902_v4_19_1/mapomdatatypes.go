// Code generated from ASN.1 module "MAP-OM-DataTypes". DO NOT EDIT.

package gsm0902_v4_19_1

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

// ActivateTraceModeArg represents the ASN.1 type ActivateTraceModeArg (SEQUENCE).
type ActivateTraceModeArg struct {
	Imsi           *IMSI          `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference TraceReference `asn1:"tag:1,context,implicit"`
	TraceType      TraceType      `asn1:"tag:2,context,implicit"`
	OmcId          *AddressString `asn1:"tag:3,context,implicit,optional" json:"OmcId,omitempty"`
	ExtCount_      int64          `asn1:"-" json:"-"`
	ExtPresent_    []bool         `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// TraceReference represents the ASN.1 type TraceReference (OCTET_STRING).
type TraceReference = []byte

// TraceType represents the ASN.1 type TraceType (INTEGER).
type TraceType = int64

// DeactivateTraceModeArg represents the ASN.1 type DeactivateTraceModeArg (SEQUENCE).
type DeactivateTraceModeArg struct {
	Imsi           *IMSI          `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference TraceReference `asn1:"tag:1,context,implicit"`
	ExtCount_      int64          `asn1:"-" json:"-"`
	ExtPresent_    []bool         `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// TraceSubscriberActivityArg represents the ASN.1 type TraceSubscriberActivityArg (SEQUENCE).
type TraceSubscriberActivityArg struct {
	Imsi           *IMSI           `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference TraceReference  `asn1:"tag:1,context,implicit"`
	TraceType      TraceType       `asn1:"tag:2,context,implicit"`
	OmcId          *AddressString  `asn1:"tag:3,context,implicit,optional" json:"OmcId,omitempty"`
	CallReference  *CallReference  `asn1:"tag:4,context,implicit,optional" json:"CallReference,omitempty"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CallReference represents the ASN.1 type CallReference (OCTET_STRING).
type CallReference = []byte

// NoteInternalHOArg represents the ASN.1 type NoteInternalHO-Arg (SEQUENCE).
type NoteInternalHOArg struct {
	HandoverType   HandoverType        `asn1:""`
	TargetCellId   *GlobalCellId       `asn1:"tag:1,context,implicit,optional" json:"TargetCellId,omitempty"`
	ChannelId      *ExternalSignalInfo `asn1:"tag:2,context,implicit,optional" json:"ChannelId,omitempty"`
	berReplayNode_ *ber.ReplayNode     `asn1:"-" json:"-"`
}

// HandoverType represents the ASN.1 ENUMERATED type HandoverType.
type HandoverType int64

const (
	HandoverTypeInterBSS HandoverType = 0
	HandoverTypeIntraBSS HandoverType = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v HandoverType) String() string {
	switch v {
	case HandoverTypeInterBSS:
		return "interBSS"
	case HandoverTypeIntraBSS:
		return "intraBSS"
	default:
		return "unknown"
	}
}

// MarshalBER encodes ActivateTraceModeArg to BER format.
func (v *ActivateTraceModeArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ActivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ActivateTraceModeArg).MarshalBER, (*ActivateTraceModeArg).marshalBER, 3)

}
func (v *ActivateTraceModeArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s471587_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s471587_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", false)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", false)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := checkEncodedValue(opts, s471587_0, "51.4", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", false)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s471587_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "omc-Id", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_omcid, encodeErr_enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		if encodeErr_enc_omcid != nil {
			return nil, qualifyBERError(encodeErr_enc_omcid, "omc-Id", "encoding", false)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, qualifyBERError(tagErr_enc_omcid, "omc-Id", "encoding", false)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s471587_0, children, i, &base_); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s471587_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ActivateTraceModeArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ActivateTraceModeArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ActivateTraceModeArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ActivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s471587_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s471587_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", true)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", true)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := checkEncodedValue(nil, s471587_0, "51.4", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", true)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s471587_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "omc-Id", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_omcid, encodeErr_enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		if encodeErr_enc_omcid != nil {
			return nil, qualifyBERError(encodeErr_enc_omcid, "omc-Id", "encoding", true)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, qualifyBERError(tagErr_enc_omcid, "omc-Id", "encoding", true)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s471587_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s471587_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ActivateTraceModeArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ActivateTraceModeArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ActivateTraceModeArg from BER/DER format.
func (destination *ActivateTraceModeArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ActivateTraceModeArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ActivateTraceModeArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe ActivateTraceModeArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s471587_0, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ActivateTraceModeArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ActivateTraceModeArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ActivateTraceModeArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ActivateTraceModeArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s471587_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceReference
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field traceReference", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("%w: expected tag [%s %d] for traceReference, got %s", ber.ErrUnexpectedElement, "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "traceReference", content[offset:])
		decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceReference", "decoding", false)
		}
		if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tracereference), "traceReference", "decoding", false)
		}
		decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "traceReference", "decoding", false)
		}
		v.TraceReference = TraceReference(decVal_tracereference)
		if offset < 0 || offset >
			len(content) || n_tracereference < 0 || n_tracereference > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_tracereference
		if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s471587_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode traceType
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field traceType", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("%w: expected tag [%s %d] for traceType, got %s", ber.ErrUnexpectedElement, "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "traceType", content[offset:])
		decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceType", "decoding", false)
		}
		if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 2 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tracetype), "traceType", "decoding", false)
		}
		if decodedTag_tracetype.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_tracetype), "traceType", "decoding", false)
		}
		decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
		if intErr != nil {
			return qualifyBERError(intErr, "traceType", "decoding", false)
		}
		v.TraceType = TraceType(decVal_tracetype)
		if offset < 0 || offset >
			len(content) || n_tracetype < 0 || n_tracetype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_tracetype
		if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
			if constraintErr := checkDecodedValue(opts, s471587_0, "51.4", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode omc-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "omc-Id", content[offset:])
				decodedTag_omcid, n_omcid, rawVal_omcid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "omc-Id", "decoding", false)
				}
				if decodedTag_omcid.Class != tag.ClassContextSpecific || decodedTag_omcid.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_omcid), "omc-Id", "decoding", false)
				}
				decVal_omcid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_omcid.Constructed, rawVal_omcid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "omc-Id", "decoding", false)
				}
				tmp_omcid := AddressString(decVal_omcid)
				v.OmcId = &tmp_omcid
				if offset < 0 || offset >
					len(content) || n_omcid < 0 || n_omcid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_omcid
				if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s471587_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "omc-Id", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ActivateTraceModeArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ActivateTraceModeArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s471587_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
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

// MarshalBER encodes DeactivateTraceModeArg to BER format.
func (v *DeactivateTraceModeArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: DeactivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*DeactivateTraceModeArg).MarshalBER, (*DeactivateTraceModeArg).marshalBER, 3)

}
func (v *DeactivateTraceModeArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s471587_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s471587_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", false)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", false)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s471587_1, children, i, &base_); err != nil {
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
func (v *DeactivateTraceModeArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes DeactivateTraceModeArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *DeactivateTraceModeArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DeactivateTraceModeArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s471587_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s471587_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", true)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", true)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s471587_1, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding DeactivateTraceModeArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *DeactivateTraceModeArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes DeactivateTraceModeArg from BER/DER format.
func (destination *DeactivateTraceModeArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: DeactivateTraceModeArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(DeactivateTraceModeArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe DeactivateTraceModeArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s471587_1, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = DeactivateTraceModeArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*DeactivateTraceModeArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding DeactivateTraceModeArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeactivateTraceModeArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s471587_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceReference
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field traceReference", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("%w: expected tag [%s %d] for traceReference, got %s", ber.ErrUnexpectedElement, "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "traceReference", content[offset:])
		decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceReference", "decoding", false)
		}
		if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tracereference), "traceReference", "decoding", false)
		}
		decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "traceReference", "decoding", false)
		}
		v.TraceReference = TraceReference(decVal_tracereference)
		if offset < 0 || offset >
			len(content) || n_tracereference < 0 || n_tracereference > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_tracereference
		if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s471587_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "DeactivateTraceModeArg", Cause: extErr_}
		}
		ber.CheckGeneratedUnknownContents(opts, content[offset:], nExt_)
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

// MarshalBER encodes TraceSubscriberActivityArg to BER format.
func (v *TraceSubscriberActivityArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: TraceSubscriberActivityArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*TraceSubscriberActivityArg).MarshalBER, (*TraceSubscriberActivityArg).marshalBER, 3)

}
func (v *TraceSubscriberActivityArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", false)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", false)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := checkEncodedValue(opts, s471587_2, "51.4", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", false)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "omc-Id", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_omcid, encodeErr_enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		if encodeErr_enc_omcid != nil {
			return nil, qualifyBERError(encodeErr_enc_omcid, "omc-Id", "encoding", false)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, qualifyBERError(tagErr_enc_omcid, "omc-Id", "encoding", false)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	if v.CallReference != nil {
		if len(*v.CallReference) < 1 || len(*v.CallReference) > 3 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "callReference", "SIZE (1..3)", len(*v.CallReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callreference, encodeErr_enc_callreference := ber.EncodeOctetString([]byte(*v.CallReference))
		if encodeErr_enc_callreference != nil {
			return nil, qualifyBERError(encodeErr_enc_callreference, "callReference", "encoding", false)
		}
		retagged_enc_callreference, tagErr_enc_callreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_callreference)
		if tagErr_enc_callreference != nil {
			return nil, qualifyBERError(tagErr_enc_callreference, "callReference", "encoding", false)
		}
		enc_callreference = retagged_enc_callreference
		children = append(children, enc_callreference...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *TraceSubscriberActivityArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes TraceSubscriberActivityArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *TraceSubscriberActivityArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TraceSubscriberActivityArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", true)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", true)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := checkEncodedValue(nil, s471587_2, "51.4", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", true)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "omc-Id", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_omcid, encodeErr_enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		if encodeErr_enc_omcid != nil {
			return nil, qualifyBERError(encodeErr_enc_omcid, "omc-Id", "encoding", true)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, qualifyBERError(tagErr_enc_omcid, "omc-Id", "encoding", true)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	if v.CallReference != nil {
		if len(*v.CallReference) < 1 || len(*v.CallReference) > 3 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "callReference", "SIZE (1..3)", len(*v.CallReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callreference, encodeErr_enc_callreference := ber.EncodeOctetString([]byte(*v.CallReference))
		if encodeErr_enc_callreference != nil {
			return nil, qualifyBERError(encodeErr_enc_callreference, "callReference", "encoding", true)
		}
		retagged_enc_callreference, tagErr_enc_callreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_callreference)
		if tagErr_enc_callreference != nil {
			return nil, qualifyBERError(tagErr_enc_callreference, "callReference", "encoding", true)
		}
		enc_callreference = retagged_enc_callreference
		children = append(children, enc_callreference...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TraceSubscriberActivityArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *TraceSubscriberActivityArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes TraceSubscriberActivityArg from BER/DER format.
func (destination *TraceSubscriberActivityArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: TraceSubscriberActivityArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(TraceSubscriberActivityArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe TraceSubscriberActivityArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s471587_2, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = TraceSubscriberActivityArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*TraceSubscriberActivityArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding TraceSubscriberActivityArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TraceSubscriberActivityArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceReference
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field traceReference", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("%w: expected tag [%s %d] for traceReference, got %s", ber.ErrUnexpectedElement, "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "traceReference", content[offset:])
		decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceReference", "decoding", false)
		}
		if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tracereference), "traceReference", "decoding", false)
		}
		decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "traceReference", "decoding", false)
		}
		v.TraceReference = TraceReference(decVal_tracereference)
		if offset < 0 || offset >
			len(content) || n_tracereference < 0 || n_tracereference > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_tracereference
		if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode traceType
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field traceType", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("%w: expected tag [%s %d] for traceType, got %s", ber.ErrUnexpectedElement, "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "traceType", content[offset:])
		decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceType", "decoding", false)
		}
		if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 2 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tracetype), "traceType", "decoding", false)
		}
		if decodedTag_tracetype.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_tracetype), "traceType", "decoding", false)
		}
		decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
		if intErr != nil {
			return qualifyBERError(intErr, "traceType", "decoding", false)
		}
		v.TraceType = TraceType(decVal_tracetype)
		if offset < 0 || offset >
			len(content) || n_tracetype < 0 || n_tracetype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_tracetype
		if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
			if constraintErr := checkDecodedValue(opts, s471587_2, "51.4", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode omc-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "omc-Id", content[offset:])
				decodedTag_omcid, n_omcid, rawVal_omcid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "omc-Id", "decoding", false)
				}
				if decodedTag_omcid.Class != tag.ClassContextSpecific || decodedTag_omcid.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_omcid), "omc-Id", "decoding", false)
				}
				decVal_omcid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_omcid.Constructed, rawVal_omcid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "omc-Id", "decoding", false)
				}
				tmp_omcid := AddressString(decVal_omcid)
				v.OmcId = &tmp_omcid
				if offset < 0 || offset >
					len(content) || n_omcid < 0 || n_omcid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_omcid
				if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "omc-Id", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode callReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "callReference", content[offset:])
				decodedTag_callreference, n_callreference, rawVal_callreference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callReference", "decoding", false)
				}
				if decodedTag_callreference.Class != tag.ClassContextSpecific || decodedTag_callreference.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_callreference), "callReference", "decoding", false)
				}
				decVal_callreference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_callreference.Constructed, rawVal_callreference, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "callReference", "decoding", false)
				}
				tmp_callreference := CallReference(decVal_callreference)
				v.CallReference = &tmp_callreference
				if offset < 0 || offset >
					len(content) || n_callreference < 0 || n_callreference > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callreference
				if len(*v.CallReference) < 1 || len(*v.CallReference) > 3 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s471587_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "callReference", "SIZE (1..3)", len(*v.CallReference)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TraceSubscriberActivityArg", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes NoteInternalHOArg to BER format.
func (v *NoteInternalHOArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: NoteInternalHOArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*NoteInternalHOArg).MarshalBER, (*NoteInternalHOArg).marshalBER, 3)

}
func (v *NoteInternalHOArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.HandoverType) != 0 && int64(v.HandoverType) != 1 {
		if constraintErr := checkEncodedValue(opts, s471587_3, "20", "handoverType", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.HandoverType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_handovertype := ber.EncodeEnumerated(int64(v.HandoverType))
	children = append(children, enc_handovertype...)
	if v.TargetCellId != nil {
		if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s471587_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(*v.TargetCellId))
		if encodeErr_enc_targetcellid != nil {
			return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", false)
		}
		retagged_enc_targetcellid, tagErr_enc_targetcellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_targetcellid)
		if tagErr_enc_targetcellid != nil {
			return nil, qualifyBERError(tagErr_enc_targetcellid, "targetCellId", "encoding", false)
		}
		enc_targetcellid = retagged_enc_targetcellid
		children = append(children, enc_targetcellid...)
	}
	if v.ChannelId != nil {
		enc_channelid, err := v.ChannelId.MarshalBER(ber.ChildEncodeOptions(opts, "channelId")...)
		if err != nil {
			return nil, qualifyBERError(err, "channelId", "encoding", false)
		}
		retagged_enc_channelid, tagErr_enc_channelid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_channelid)
		if tagErr_enc_channelid != nil {
			return nil, qualifyBERError(tagErr_enc_channelid, "channelId", "encoding", false)
		}
		enc_channelid = retagged_enc_channelid
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_channelid)
		children = append(children, enc_channelid...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *NoteInternalHOArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes NoteInternalHOArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *NoteInternalHOArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoteInternalHOArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.HandoverType) != 0 && int64(v.HandoverType) != 1 {
		if constraintErr := checkEncodedValue(nil, s471587_3, "20", "handoverType", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.HandoverType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_handovertype := ber.EncodeEnumerated(int64(v.HandoverType))
	children = append(children, enc_handovertype...)
	if v.TargetCellId != nil {
		if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s471587_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(*v.TargetCellId))
		if encodeErr_enc_targetcellid != nil {
			return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", true)
		}
		retagged_enc_targetcellid, tagErr_enc_targetcellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_targetcellid)
		if tagErr_enc_targetcellid != nil {
			return nil, qualifyBERError(tagErr_enc_targetcellid, "targetCellId", "encoding", true)
		}
		enc_targetcellid = retagged_enc_targetcellid
		children = append(children, enc_targetcellid...)
	}
	if v.ChannelId != nil {
		enc_channelid, err := v.ChannelId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "channelId", "encoding", true)
		}
		retagged_enc_channelid, tagErr_enc_channelid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_channelid)
		if tagErr_enc_channelid != nil {
			return nil, qualifyBERError(tagErr_enc_channelid, "channelId", "encoding", true)
		}
		enc_channelid = retagged_enc_channelid
		children = append(children, enc_channelid...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding NoteInternalHOArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *NoteInternalHOArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes NoteInternalHOArg from BER/DER format.
func (destination *NoteInternalHOArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: NoteInternalHOArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(NoteInternalHOArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe NoteInternalHOArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s471587_3, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = NoteInternalHOArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*NoteInternalHOArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding NoteInternalHOArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoteInternalHOArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode handoverType
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field handoverType", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "handoverType", content[offset:])
		val_handovertype, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "handoverType", "decoding", false)
		}
		v.HandoverType = HandoverType(val_handovertype)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.HandoverType) != 0 && int64(v.HandoverType) != 1 {
			if constraintErr := checkDecodedValue(opts, s471587_3, "20", "handoverType", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.HandoverType))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode targetCellId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "targetCellId", content[offset:])
				decodedTag_targetcellid, n_targetcellid, rawVal_targetcellid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "targetCellId", "decoding", false)
				}
				if decodedTag_targetcellid.Class != tag.ClassContextSpecific || decodedTag_targetcellid.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_targetcellid), "targetCellId", "decoding", false)
				}
				decVal_targetcellid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_targetcellid.Constructed, rawVal_targetcellid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "targetCellId", "decoding", false)
				}
				tmp_targetcellid := GlobalCellId(decVal_targetcellid)
				v.TargetCellId = &tmp_targetcellid
				if offset < 0 || offset >
					len(content) || n_targetcellid < 0 || n_targetcellid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_targetcellid
				if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s471587_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode channelId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "channelId", content[offset:])
				decodedTag_channelid, n_channelid, rawVal_channelid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "channelId", "decoding", false)
				}
				if decodedTag_channelid.Class != tag.ClassContextSpecific || decodedTag_channelid.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_channelid), "channelId", "decoding", false)
				}
				if decodedTag_channelid.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_channelid), "channelId", "decoding", false)
				}
				_ = rawVal_channelid
				if offset < 0 || offset >
					len(content) || n_channelid < 0 || n_channelid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_channelid, reconstructionErr_channelid := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_channelid])
				if reconstructionErr_channelid != nil {
					return qualifyBERError(reconstructionErr_channelid, "channelId", "decoding", false)
				}
				var dec_channelid ExternalSignalInfo
				if unmErr := dec_channelid.UnmarshalBER(reconstructed_channelid, ber.ChildDecodeOptions(opts, "channelId")...); unmErr != nil {
					return qualifyBERError(unmErr, "channelId", "decoding", false)
				}
				v.ChannelId = &dec_channelid
				if offset < 0 || offset >
					len(content) || n_channelid < 0 || n_channelid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_channelid
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "NoteInternalHOArg", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

const (
	s471587_0 = "MAP-OM-DataTypes.ActivateTraceModeArg"
	s471587_1 = "MAP-OM-DataTypes.DeactivateTraceModeArg"
	s471587_2 = "MAP-OM-DataTypes.TraceSubscriberActivityArg"
	s471587_3 = "MAP-OM-DataTypes.NoteInternalHO-Arg"
)
