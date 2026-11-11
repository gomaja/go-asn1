// Code generated from ASN.1 module "MAP-AbortInformation". DO NOT EDIT.

package gsm0902_v3_11_0

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

// MAPAbortInformation represents the ASN.1 type MAPAbortInformation (SEQUENCE).
type MAPAbortInformation struct {
	AbortCause            int64           `asn1:""`
	AdditionalInformation []byte          `asn1:""`
	berReplayNode_        *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes MAPAbortInformation to BER format.
func (v *MAPAbortInformation) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MAPAbortInformation receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MAPAbortInformation).MarshalBER, (*MAPAbortInformation).marshalBER, 3)

}
func (v *MAPAbortInformation) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.AbortCause) != 0 && int64(v.AbortCause) != 1 && int64(v.AbortCause) != 2 && int64(v.AbortCause) != 3 && int64(v.AbortCause) != 4 && int64(v.AbortCause) != 5 && int64(v.AbortCause) != 6 && int64(v.AbortCause) != 7 && int64(v.AbortCause) != 8 && int64(v.AbortCause) != 9 {
		if constraintErr := checkEncodedValue(opts, s438408_0, "15", "abortCause", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}", ber.ObserveInteger(int64(v.AbortCause))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_abortcause := ber.EncodeEnumerated(int64(v.AbortCause))
	children = append(children, enc_abortcause...)
	if len(v.AdditionalInformation) < 1 || len(v.AdditionalInformation) > 200 {
		if constraintErr := checkEncodedLength(opts, s438408_0, "37.4", "additionalInformation", "SIZE (1..200)", len(v.AdditionalInformation)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_additionalinformation, encodeErr_enc_additionalinformation := ber.EncodeOctetString(v.AdditionalInformation)
	if encodeErr_enc_additionalinformation != nil {
		return nil, qualifyBERError(encodeErr_enc_additionalinformation, "additionalInformation", "encoding", false)
	}
	children = append(children, enc_additionalinformation...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MAPAbortInformation) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MAPAbortInformation to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MAPAbortInformation) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MAPAbortInformation receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.AbortCause) != 0 && int64(v.AbortCause) != 1 && int64(v.AbortCause) != 2 && int64(v.AbortCause) != 3 && int64(v.AbortCause) != 4 && int64(v.AbortCause) != 5 && int64(v.AbortCause) != 6 && int64(v.AbortCause) != 7 && int64(v.AbortCause) != 8 && int64(v.AbortCause) != 9 {
		if constraintErr := checkEncodedValue(nil, s438408_0, "15", "abortCause", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}", ber.ObserveInteger(int64(v.AbortCause))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_abortcause := ber.EncodeEnumerated(int64(v.AbortCause))
	children = append(children, enc_abortcause...)
	if len(v.AdditionalInformation) < 1 || len(v.AdditionalInformation) > 200 {
		if constraintErr := checkEncodedLength(nil, s438408_0, "37.4", "additionalInformation", "SIZE (1..200)", len(v.AdditionalInformation)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_additionalinformation, encodeErr_enc_additionalinformation := ber.EncodeOctetString(v.AdditionalInformation)
	if encodeErr_enc_additionalinformation != nil {
		return nil, qualifyBERError(encodeErr_enc_additionalinformation, "additionalInformation", "encoding", true)
	}
	children = append(children, enc_additionalinformation...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding MAPAbortInformation as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MAPAbortInformation) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MAPAbortInformation from BER/DER format.
func (destination *MAPAbortInformation) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MAPAbortInformation destination is nil", ber.ErrInvalidValue)
	}
	v := new(MAPAbortInformation)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe MAPAbortInformation
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s438408_0, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MAPAbortInformation{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MAPAbortInformation).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MAPAbortInformation SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPAbortInformation", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode abortCause
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field abortCause", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "abortCause", content[offset:])
		val_abortcause, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "abortCause", "decoding", false)
		}
		v.AbortCause = val_abortcause
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.AbortCause) != 0 && int64(v.AbortCause) != 1 && int64(v.AbortCause) != 2 && int64(v.AbortCause) != 3 && int64(v.AbortCause) != 4 && int64(v.AbortCause) != 5 && int64(v.AbortCause) != 6 && int64(v.AbortCause) != 7 && int64(v.AbortCause) != 8 && int64(v.AbortCause) != 9 {
			if constraintErr := checkDecodedValue(opts, s438408_0, "15", "abortCause", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}", ber.ObserveInteger(int64(v.AbortCause))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode additionalInformation
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field additionalInformation", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "additionalInformation", content[offset:])
		val_additionalinformation, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "additionalInformation", "decoding", false)
		}
		v.AdditionalInformation = val_additionalinformation
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.AdditionalInformation) < 1 || len(v.AdditionalInformation) > 200 {
			if constraintErr := checkDecodedLength(opts, s438408_0, "37.4", "additionalInformation", "SIZE (1..200)", len(v.AdditionalInformation)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "MAPAbortInformation", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

const s438408_0 = "MAP-AbortInformation.MAPAbortInformation"
