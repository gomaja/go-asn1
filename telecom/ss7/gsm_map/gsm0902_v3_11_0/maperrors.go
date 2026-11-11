// Code generated from ASN.1 module "MAP-Errors". DO NOT EDIT.

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

// CallBarredParameter represents the ASN.1 ENUMERATED type CallBarred-parameter.
type CallBarredParameter int64

const (
	CallBarredParameterBarringServiceActive CallBarredParameter = 0
	CallBarredParameterOperatorBarring      CallBarredParameter = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CallBarredParameter) String() string {
	switch v {
	case CallBarredParameterBarringServiceActive:
		return "barringServiceActive"
	case CallBarredParameterOperatorBarring:
		return "operatorBarring"
	default:
		return "unknown"
	}
}

// CUGRejectParameter represents the ASN.1 ENUMERATED type CUG-Reject-parameter.
type CUGRejectParameter int64

const (
	CUGRejectParameterIncomingCallBarred CUGRejectParameter = 0
	CUGRejectParameterNonCUGmember       CUGRejectParameter = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CUGRejectParameter) String() string {
	switch v {
	case CUGRejectParameterIncomingCallBarred:
		return "incomingCallBarred"
	case CUGRejectParameterNonCUGmember:
		return "nonCUGmember"
	default:
		return "unknown"
	}
}

// PasswordRegistrationFailureParameter represents the ASN.1 ENUMERATED type PasswordRegistrationFailure-parameter.
type PasswordRegistrationFailureParameter int64

const (
	PasswordRegistrationFailureParameterUndetermined         PasswordRegistrationFailureParameter = 0
	PasswordRegistrationFailureParameterInvalidFormat        PasswordRegistrationFailureParameter = 1
	PasswordRegistrationFailureParameterNewPasswordsMismatch PasswordRegistrationFailureParameter = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v PasswordRegistrationFailureParameter) String() string {
	switch v {
	case PasswordRegistrationFailureParameterUndetermined:
		return "undetermined"
	case PasswordRegistrationFailureParameterInvalidFormat:
		return "invalidFormat"
	case PasswordRegistrationFailureParameterNewPasswordsMismatch:
		return "newPasswordsMismatch"
	default:
		return "unknown"
	}
}

// SMDeliveryFailureParameter represents the ASN.1 ENUMERATED type SM-DeliveryFailure-parameter.
type SMDeliveryFailureParameter int64

const (
	SMDeliveryFailureParameterMemoryCapacityExceeded SMDeliveryFailureParameter = 0
	SMDeliveryFailureParameterMsProtocolError        SMDeliveryFailureParameter = 1
	SMDeliveryFailureParameterMsNotEquiped           SMDeliveryFailureParameter = 2
	SMDeliveryFailureParameterUnknownServiceCentre   SMDeliveryFailureParameter = 3
	SMDeliveryFailureParameterScCongestion           SMDeliveryFailureParameter = 4
	SMDeliveryFailureParameterInvalidSmeAddress      SMDeliveryFailureParameter = 5
	SMDeliveryFailureParameterMsNotScSubscriber      SMDeliveryFailureParameter = 6
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v SMDeliveryFailureParameter) String() string {
	switch v {
	case SMDeliveryFailureParameterMemoryCapacityExceeded:
		return "memoryCapacityExceeded"
	case SMDeliveryFailureParameterMsProtocolError:
		return "msProtocolError"
	case SMDeliveryFailureParameterMsNotEquiped:
		return "msNotEquiped"
	case SMDeliveryFailureParameterUnknownServiceCentre:
		return "unknownServiceCentre"
	case SMDeliveryFailureParameterScCongestion:
		return "scCongestion"
	case SMDeliveryFailureParameterInvalidSmeAddress:
		return "invalidSmeAddress"
	case SMDeliveryFailureParameterMsNotScSubscriber:
		return "msNotScSubscriber"
	default:
		return "unknown"
	}
}

// SSIncompatibilityParameter represents the ASN.1 type SS-Incompatibility-parameter (SEQUENCE).
type SSIncompatibilityParameter struct {
	SsCode         *SSCode           `asn1:"tag:1,context,implicit,optional" json:"SsCode,omitempty"`
	BasicService   *BasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus       *SSStatus         `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// MarshalBER encodes SSIncompatibilityParameter to BER format.
func (v *SSIncompatibilityParameter) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSIncompatibilityParameter receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSIncompatibilityParameter).MarshalBER, (*SSIncompatibilityParameter).marshalBER, 3)

}
func (v *SSIncompatibilityParameter) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := checkEncodedLength(opts, s399b01_0, "37.4", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
		}
		retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sscode)
		if tagErr_enc_sscode != nil {
			return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", false)
		}
		enc_sscode = retagged_enc_sscode
		children = append(children, enc_sscode...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(ber.ChildEncodeOptions(opts, "basicService")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservice)
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := checkEncodedLength(opts, s399b01_0, "37.4", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", false)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", false)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSIncompatibilityParameter) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSIncompatibilityParameter to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSIncompatibilityParameter) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSIncompatibilityParameter receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := checkEncodedLength(nil, s399b01_0, "37.4", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
		}
		retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sscode)
		if tagErr_enc_sscode != nil {
			return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", true)
		}
		enc_sscode = retagged_enc_sscode
		children = append(children, enc_sscode...)
	}
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", true)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := checkEncodedLength(nil, s399b01_0, "37.4", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", true)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", true)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SSIncompatibilityParameter as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSIncompatibilityParameter) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSIncompatibilityParameter from BER/DER format.
func (destination *SSIncompatibilityParameter) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSIncompatibilityParameter destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSIncompatibilityParameter)

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
			var probe SSIncompatibilityParameter
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s399b01_0, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSIncompatibilityParameter{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSIncompatibilityParameter).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSIncompatibilityParameter SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSIncompatibilityParameter", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
				decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Code", "decoding", false)
				}
				if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_sscode), "ss-Code", "decoding", false)
				}
				decVal_sscode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sscode.Constructed, rawVal_sscode, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "ss-Code", "decoding", false)
				}
				tmp_sscode := SSCode(decVal_sscode)
				v.SsCode = &tmp_sscode
				if offset > len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sscode
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := checkDecodedLength(opts, s399b01_0, "37.4", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				ber.MarkPreflightTarget(opts, "basicService", content[offset:])
				// Decode nested CHOICE (BasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return qualifyBERError(tlvErr_basicservice, "basicService", "decoding", false)
				}
				var dec_basicservice BasicServiceCode
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicService", "decoding", false)
				}
				v.BasicService = &dec_basicservice
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservice
			}
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "ss-Status", content[offset:])
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Status", "decoding", false)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_ssstatus), "ss-Status", "decoding", false)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "ss-Status", "decoding", false)
				}
				tmp_ssstatus := SSStatus(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := checkDecodedLength(opts, s399b01_0, "37.4", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SSIncompatibilityParameter", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

const s399b01_0 = "MAP-Errors.SS-Incompatibility-parameter"
