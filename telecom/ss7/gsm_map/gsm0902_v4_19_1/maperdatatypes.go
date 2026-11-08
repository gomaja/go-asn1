// Code generated from ASN.1 module "MAP-ER-DataTypes". DO NOT EDIT.

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

// RoamingNotAllowedCause represents the ASN.1 ENUMERATED type RoamingNotAllowedCause.
type RoamingNotAllowedCause int64

const (
	RoamingNotAllowedCausePlmnRoamingNotAllowed     RoamingNotAllowedCause = 0
	RoamingNotAllowedCauseOperatorDeterminedBarring RoamingNotAllowedCause = 3
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v RoamingNotAllowedCause) String() string {
	switch v {
	case RoamingNotAllowedCausePlmnRoamingNotAllowed:
		return "plmnRoamingNotAllowed"
	case RoamingNotAllowedCauseOperatorDeterminedBarring:
		return "operatorDeterminedBarring"
	default:
		return "unknown"
	}
}

// CallBarringCause represents the ASN.1 ENUMERATED type CallBarringCause.
type CallBarringCause int64

const (
	CallBarringCauseBarringServiceActive CallBarringCause = 0
	CallBarringCauseOperatorBarring      CallBarringCause = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CallBarringCause) String() string {
	switch v {
	case CallBarringCauseBarringServiceActive:
		return "barringServiceActive"
	case CallBarringCauseOperatorBarring:
		return "operatorBarring"
	default:
		return "unknown"
	}
}

// CUGRejectCause represents the ASN.1 ENUMERATED type CUG-RejectCause.
type CUGRejectCause int64

const (
	CUGRejectCauseIncomingCallsBarredWithinCUG                CUGRejectCause = 0
	CUGRejectCauseSubscriberNotMemberOfCUG                    CUGRejectCause = 1
	CUGRejectCauseRequestedBasicServiceViolatesCUGConstraints CUGRejectCause = 5
	CUGRejectCauseCalledPartySSInteractionViolation           CUGRejectCause = 7
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CUGRejectCause) String() string {
	switch v {
	case CUGRejectCauseIncomingCallsBarredWithinCUG:
		return "incomingCallsBarredWithinCUG"
	case CUGRejectCauseSubscriberNotMemberOfCUG:
		return "subscriberNotMemberOfCUG"
	case CUGRejectCauseRequestedBasicServiceViolatesCUGConstraints:
		return "requestedBasicServiceViolatesCUG-Constraints"
	case CUGRejectCauseCalledPartySSInteractionViolation:
		return "calledPartySS-InteractionViolation"
	default:
		return "unknown"
	}
}

// SSIncompatibilityCause represents the ASN.1 type SS-IncompatibilityCause (SEQUENCE).
type SSIncompatibilityCause struct {
	SsCode       *SSCode           `asn1:"tag:1,context,implicit,optional" json:"SsCode,omitempty"`
	BasicService *BasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSStatus         `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64             `asn1:"-" json:"-"`
	ExtPresent_  []bool            `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// PWRegistrationFailureCause represents the ASN.1 ENUMERATED type PW-RegistrationFailureCause.
type PWRegistrationFailureCause int64

const (
	PWRegistrationFailureCauseUndetermined         PWRegistrationFailureCause = 0
	PWRegistrationFailureCauseInvalidFormat        PWRegistrationFailureCause = 1
	PWRegistrationFailureCauseNewPasswordsMismatch PWRegistrationFailureCause = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v PWRegistrationFailureCause) String() string {
	switch v {
	case PWRegistrationFailureCauseUndetermined:
		return "undetermined"
	case PWRegistrationFailureCauseInvalidFormat:
		return "invalidFormat"
	case PWRegistrationFailureCauseNewPasswordsMismatch:
		return "newPasswordsMismatch"
	default:
		return "unknown"
	}
}

// SMDeliveryFailureCause choice constants.
const (
	SMDeliveryFailureCauseChoiceSmDeliveryFailureCauseWithDiagnostic = 1
	SMDeliveryFailureCauseChoiceSmEnumeratedDeliveryFailureCause     = 2
)

// SMDeliveryFailureCause represents the ASN.1 CHOICE type SM-DeliveryFailureCause.
type SMDeliveryFailureCause struct {
	Choice                               int
	berReplayNode_                       *ber.ReplayNode                       `json:"-"`
	SmDeliveryFailureCauseWithDiagnostic *SMDeliveryFailureCauseWithDiagnostic `json:"SmDeliveryFailureCauseWithDiagnostic,omitempty"`
	SmEnumeratedDeliveryFailureCause     *SMEnumeratedDeliveryFailureCause     `json:"SmEnumeratedDeliveryFailureCause,omitempty"`
}

// NewSMDeliveryFailureCauseSmDeliveryFailureCauseWithDiagnostic creates a SMDeliveryFailureCause with the sm-DeliveryFailureCauseWithDiagnostic alternative.
func NewSMDeliveryFailureCauseSmDeliveryFailureCauseWithDiagnostic(v SMDeliveryFailureCauseWithDiagnostic) SMDeliveryFailureCause {
	return SMDeliveryFailureCause{
		Choice:                               SMDeliveryFailureCauseChoiceSmDeliveryFailureCauseWithDiagnostic,
		SmDeliveryFailureCauseWithDiagnostic: &v,
	}
}

// NewSMDeliveryFailureCauseSmEnumeratedDeliveryFailureCause creates a SMDeliveryFailureCause with the sm-EnumeratedDeliveryFailureCause alternative.
func NewSMDeliveryFailureCauseSmEnumeratedDeliveryFailureCause(v SMEnumeratedDeliveryFailureCause) SMDeliveryFailureCause {
	return SMDeliveryFailureCause{
		Choice:                           SMDeliveryFailureCauseChoiceSmEnumeratedDeliveryFailureCause,
		SmEnumeratedDeliveryFailureCause: &v,
	}
}

// SMEnumeratedDeliveryFailureCause represents the ASN.1 ENUMERATED type SM-EnumeratedDeliveryFailureCause.
type SMEnumeratedDeliveryFailureCause int64

const (
	SMEnumeratedDeliveryFailureCauseMemoryCapacityExceeded    SMEnumeratedDeliveryFailureCause = 0
	SMEnumeratedDeliveryFailureCauseEquipmentProtocolError    SMEnumeratedDeliveryFailureCause = 1
	SMEnumeratedDeliveryFailureCauseEquipmentNotSMEquipped    SMEnumeratedDeliveryFailureCause = 2
	SMEnumeratedDeliveryFailureCauseUnknownServiceCentre      SMEnumeratedDeliveryFailureCause = 3
	SMEnumeratedDeliveryFailureCauseScCongestion              SMEnumeratedDeliveryFailureCause = 4
	SMEnumeratedDeliveryFailureCauseInvalidSMEAddress         SMEnumeratedDeliveryFailureCause = 5
	SMEnumeratedDeliveryFailureCauseSubscriberNotSCSubscriber SMEnumeratedDeliveryFailureCause = 6
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v SMEnumeratedDeliveryFailureCause) String() string {
	switch v {
	case SMEnumeratedDeliveryFailureCauseMemoryCapacityExceeded:
		return "memoryCapacityExceeded"
	case SMEnumeratedDeliveryFailureCauseEquipmentProtocolError:
		return "equipmentProtocolError"
	case SMEnumeratedDeliveryFailureCauseEquipmentNotSMEquipped:
		return "equipmentNotSM-Equipped"
	case SMEnumeratedDeliveryFailureCauseUnknownServiceCentre:
		return "unknownServiceCentre"
	case SMEnumeratedDeliveryFailureCauseScCongestion:
		return "sc-Congestion"
	case SMEnumeratedDeliveryFailureCauseInvalidSMEAddress:
		return "invalidSME-Address"
	case SMEnumeratedDeliveryFailureCauseSubscriberNotSCSubscriber:
		return "subscriberNotSC-Subscriber"
	default:
		return "unknown"
	}
}

// SMDeliveryFailureCauseWithDiagnostic represents the ASN.1 type SM-DeliveryFailureCauseWithDiagnostic (SEQUENCE).
type SMDeliveryFailureCauseWithDiagnostic struct {
	SmEnumeratedDeliveryFailureCause SMEnumeratedDeliveryFailureCause `asn1:""`
	DiagnosticInfo                   *SignalInfo                      `asn1:",optional" json:"DiagnosticInfo,omitempty"`
	ExtCount_                        int64                            `asn1:"-" json:"-"`
	ExtPresent_                      []bool                           `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes SSIncompatibilityCause to BER format.
func (v *SSIncompatibilityCause) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSIncompatibilityCause receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSIncompatibilityCause).MarshalBER, (*SSIncompatibilityCause).marshalBER, 3)

}
func (v *SSIncompatibilityCause) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, sacca98_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, sacca98_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sacca98_0, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sacca98_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSIncompatibilityCause) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSIncompatibilityCause to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSIncompatibilityCause) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSIncompatibilityCause receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, sacca98_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, sacca98_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sacca98_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sacca98_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSIncompatibilityCause as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSIncompatibilityCause) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSIncompatibilityCause from BER/DER format.
func (destination *SSIncompatibilityCause) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSIncompatibilityCause destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSIncompatibilityCause)

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
			var probe SSIncompatibilityCause
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sacca98_0, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSIncompatibilityCause{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSIncompatibilityCause).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSIncompatibilityCause SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSIncompatibilityCause", Cause: ber.ErrExtraData}
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, sacca98_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, sacca98_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSIncompatibilityCause", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSIncompatibilityCause", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sacca98_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMDeliveryFailureCause to BER format.
func (v *SMDeliveryFailureCause) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SMDeliveryFailureCause receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SMDeliveryFailureCause).MarshalBER, (*SMDeliveryFailureCause).marshalBER, 3)

}
func (v *SMDeliveryFailureCause) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SMDeliveryFailureCause) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SMDeliveryFailureCauseChoiceSmDeliveryFailureCauseWithDiagnostic:
		if v.SmDeliveryFailureCauseWithDiagnostic == nil {
			return nil, fmt.Errorf("%w: choice SMDeliveryFailureCause: sm-DeliveryFailureCauseWithDiagnostic is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.SmDeliveryFailureCauseWithDiagnostic.MarshalBER(ber.ChildEncodeOptions(opts, "sm-DeliveryFailureCauseWithDiagnostic")...)
		if err != nil {
			return nil, qualifyBERError(err, "sm-DeliveryFailureCauseWithDiagnostic", "encoding", false)
		}
		return enc_0, nil
	case SMDeliveryFailureCauseChoiceSmEnumeratedDeliveryFailureCause:
		if v.SmEnumeratedDeliveryFailureCause == nil {
			return nil, fmt.Errorf("%w: choice SMDeliveryFailureCause: sm-EnumeratedDeliveryFailureCause is nil", ber.ErrInvalidValue)
		}
		enc_1 := ber.EncodeEnumerated(int64(*v.SmEnumeratedDeliveryFailureCause))
		if int64(*v.SmEnumeratedDeliveryFailureCause) != 0 && int64(*v.SmEnumeratedDeliveryFailureCause) != 1 && int64(*v.SmEnumeratedDeliveryFailureCause) != 2 && int64(*v.SmEnumeratedDeliveryFailureCause) != 3 && int64(*v.SmEnumeratedDeliveryFailureCause) != 4 && int64(*v.SmEnumeratedDeliveryFailureCause) != 5 && int64(*v.SmEnumeratedDeliveryFailureCause) != 6 {
			if constraintErr := checkEncodedValue(opts, "MAP-ER-DataTypes.SM-DeliveryFailureCause", "20", "sm-EnumeratedDeliveryFailureCause", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", ber.ObserveInteger(int64(*v.SmEnumeratedDeliveryFailureCause))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMDeliveryFailureCause", v.Choice)
	}
}

// MarshalDER encodes SMDeliveryFailureCause to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SMDeliveryFailureCause) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMDeliveryFailureCause receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SMDeliveryFailureCauseChoiceSmDeliveryFailureCauseWithDiagnostic:
		if v.SmDeliveryFailureCauseWithDiagnostic == nil {
			return nil, fmt.Errorf("%w: choice SMDeliveryFailureCause: sm-DeliveryFailureCauseWithDiagnostic is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.SmDeliveryFailureCauseWithDiagnostic.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "sm-DeliveryFailureCauseWithDiagnostic", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "sm-DeliveryFailureCauseWithDiagnostic", "encoding", true)
		}
		return enc_der_0, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SMDeliveryFailureCauseChoiceSmDeliveryFailureCauseWithDiagnostic:
			return nil, qualifyBERError(err, "sm-DeliveryFailureCauseWithDiagnostic", "encoding", true)
		case SMDeliveryFailureCauseChoiceSmEnumeratedDeliveryFailureCause:
			return nil, qualifyBERError(err, "sm-EnumeratedDeliveryFailureCause", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SMDeliveryFailureCause as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SMDeliveryFailureCause) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMDeliveryFailureCause from BER/DER format.
func (destination *SMDeliveryFailureCause) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SMDeliveryFailureCause destination is nil", ber.ErrInvalidValue)
	}
	v := new(SMDeliveryFailureCause)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SMDeliveryFailureCause).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SMDeliveryFailureCause
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-ER-DataTypes.SM-DeliveryFailureCause", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SMDeliveryFailureCause{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMDeliveryFailureCause CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMDeliveryFailureCause: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SMDeliveryFailureCause CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMDeliveryFailureCause", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SMDeliveryFailureCause.sm-DeliveryFailureCauseWithDiagnostic", "decoding", false)
	}
	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SMDeliveryFailureCause.sm-EnumeratedDeliveryFailureCause", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = SMDeliveryFailureCauseChoiceSmDeliveryFailureCauseWithDiagnostic
		ber.MarkPreflightTarget(opts, "sm-DeliveryFailureCauseWithDiagnostic", choiceData)
		var dec SMDeliveryFailureCauseWithDiagnostic
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "sm-DeliveryFailureCauseWithDiagnostic")...); unmErr != nil {
			return qualifyBERError(unmErr, "sm-DeliveryFailureCauseWithDiagnostic", "decoding", false)
		}
		v.SmDeliveryFailureCauseWithDiagnostic = &dec
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 && peekTag.Constructed == false {
		v.Choice = SMDeliveryFailureCauseChoiceSmEnumeratedDeliveryFailureCause
		ber.MarkPreflightTarget(opts, "sm-EnumeratedDeliveryFailureCause", choiceData)
		decVal, _, intErr := ber.DecodeEnumerated(choiceData, opts...)
		if intErr != nil {
			return qualifyBERError(intErr, "sm-EnumeratedDeliveryFailureCause", "decoding", false)
		}
		tmp := SMEnumeratedDeliveryFailureCause(decVal)
		v.SmEnumeratedDeliveryFailureCause = &tmp
		if int64(*v.SmEnumeratedDeliveryFailureCause) != 0 && int64(*v.SmEnumeratedDeliveryFailureCause) != 1 && int64(*v.SmEnumeratedDeliveryFailureCause) != 2 && int64(*v.SmEnumeratedDeliveryFailureCause) != 3 && int64(*v.SmEnumeratedDeliveryFailureCause) != 4 && int64(*v.SmEnumeratedDeliveryFailureCause) != 5 && int64(*v.SmEnumeratedDeliveryFailureCause) != 6 {
			if constraintErr := checkDecodedValue(opts, "MAP-ER-DataTypes.SM-DeliveryFailureCause", "20", "sm-EnumeratedDeliveryFailureCause", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", ber.ObserveInteger(int64(*v.SmEnumeratedDeliveryFailureCause))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for SMDeliveryFailureCause CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes SMDeliveryFailureCauseWithDiagnostic to BER format.
func (v *SMDeliveryFailureCauseWithDiagnostic) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SMDeliveryFailureCauseWithDiagnostic receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SMDeliveryFailureCauseWithDiagnostic).MarshalBER, (*SMDeliveryFailureCauseWithDiagnostic).marshalBER, 3)

}
func (v *SMDeliveryFailureCauseWithDiagnostic) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.SmEnumeratedDeliveryFailureCause) != 0 && int64(v.SmEnumeratedDeliveryFailureCause) != 1 && int64(v.SmEnumeratedDeliveryFailureCause) != 2 && int64(v.SmEnumeratedDeliveryFailureCause) != 3 && int64(v.SmEnumeratedDeliveryFailureCause) != 4 && int64(v.SmEnumeratedDeliveryFailureCause) != 5 && int64(v.SmEnumeratedDeliveryFailureCause) != 6 {
		if constraintErr := checkEncodedValue(opts, sacca98_1, "20", "sm-EnumeratedDeliveryFailureCause", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", ber.ObserveInteger(int64(v.SmEnumeratedDeliveryFailureCause))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smenumerateddeliveryfailurecause := ber.EncodeEnumerated(int64(v.SmEnumeratedDeliveryFailureCause))
	children = append(children, enc_smenumerateddeliveryfailurecause...)
	if v.DiagnosticInfo != nil {
		if len(*v.DiagnosticInfo) < 1 || len(*v.DiagnosticInfo) > 200 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, sacca98_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "diagnosticInfo", "SIZE (1..200)", len(*v.DiagnosticInfo)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_diagnosticinfo, encodeErr_enc_diagnosticinfo := ber.EncodeOctetString([]byte(*v.DiagnosticInfo))
		if encodeErr_enc_diagnosticinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_diagnosticinfo, "diagnosticInfo", "encoding", false)
		}
		children = append(children, enc_diagnosticinfo...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sacca98_1, children, i, &base_); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sacca98_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SMDeliveryFailureCauseWithDiagnostic) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SMDeliveryFailureCauseWithDiagnostic to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SMDeliveryFailureCauseWithDiagnostic) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMDeliveryFailureCauseWithDiagnostic receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.SmEnumeratedDeliveryFailureCause) != 0 && int64(v.SmEnumeratedDeliveryFailureCause) != 1 && int64(v.SmEnumeratedDeliveryFailureCause) != 2 && int64(v.SmEnumeratedDeliveryFailureCause) != 3 && int64(v.SmEnumeratedDeliveryFailureCause) != 4 && int64(v.SmEnumeratedDeliveryFailureCause) != 5 && int64(v.SmEnumeratedDeliveryFailureCause) != 6 {
		if constraintErr := checkEncodedValue(nil, sacca98_1, "20", "sm-EnumeratedDeliveryFailureCause", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", ber.ObserveInteger(int64(v.SmEnumeratedDeliveryFailureCause))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smenumerateddeliveryfailurecause := ber.EncodeEnumerated(int64(v.SmEnumeratedDeliveryFailureCause))
	children = append(children, enc_smenumerateddeliveryfailurecause...)
	if v.DiagnosticInfo != nil {
		if len(*v.DiagnosticInfo) < 1 || len(*v.DiagnosticInfo) > 200 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, sacca98_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "diagnosticInfo", "SIZE (1..200)", len(*v.DiagnosticInfo)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_diagnosticinfo, encodeErr_enc_diagnosticinfo := ber.EncodeOctetString([]byte(*v.DiagnosticInfo))
		if encodeErr_enc_diagnosticinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_diagnosticinfo, "diagnosticInfo", "encoding", true)
		}
		children = append(children, enc_diagnosticinfo...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sacca98_1, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sacca98_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SMDeliveryFailureCauseWithDiagnostic as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SMDeliveryFailureCauseWithDiagnostic) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMDeliveryFailureCauseWithDiagnostic from BER/DER format.
func (destination *SMDeliveryFailureCauseWithDiagnostic) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SMDeliveryFailureCauseWithDiagnostic destination is nil", ber.ErrInvalidValue)
	}
	v := new(SMDeliveryFailureCauseWithDiagnostic)

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
			var probe SMDeliveryFailureCauseWithDiagnostic
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sacca98_1, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SMDeliveryFailureCauseWithDiagnostic{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SMDeliveryFailureCauseWithDiagnostic).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SMDeliveryFailureCauseWithDiagnostic SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SMDeliveryFailureCauseWithDiagnostic", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-EnumeratedDeliveryFailureCause
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field sm-EnumeratedDeliveryFailureCause", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "sm-EnumeratedDeliveryFailureCause", content[offset:])
		val_smenumerateddeliveryfailurecause, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "sm-EnumeratedDeliveryFailureCause", "decoding", false)
		}
		v.SmEnumeratedDeliveryFailureCause = SMEnumeratedDeliveryFailureCause(val_smenumerateddeliveryfailurecause)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.SmEnumeratedDeliveryFailureCause) != 0 && int64(v.SmEnumeratedDeliveryFailureCause) != 1 && int64(v.SmEnumeratedDeliveryFailureCause) != 2 && int64(v.SmEnumeratedDeliveryFailureCause) != 3 && int64(v.SmEnumeratedDeliveryFailureCause) != 4 && int64(v.SmEnumeratedDeliveryFailureCause) != 5 && int64(v.SmEnumeratedDeliveryFailureCause) != 6 {
			if constraintErr := checkDecodedValue(opts, sacca98_1, "20", "sm-EnumeratedDeliveryFailureCause", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", ber.ObserveInteger(int64(v.SmEnumeratedDeliveryFailureCause))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode diagnosticInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "diagnosticInfo", content[offset:])
				val_diagnosticinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "diagnosticInfo", "decoding", false)
				}
				tmp_diagnosticinfo := SignalInfo(val_diagnosticinfo)
				v.DiagnosticInfo = &tmp_diagnosticinfo
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.DiagnosticInfo) < 1 || len(*v.DiagnosticInfo) > 200 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, sacca98_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "diagnosticInfo", "SIZE (1..200)", len(*v.DiagnosticInfo)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SMDeliveryFailureCauseWithDiagnostic", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SMDeliveryFailureCauseWithDiagnostic", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sacca98_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

const (
	sacca98_0 = "MAP-ER-DataTypes.SS-IncompatibilityCause"
	sacca98_1 = "MAP-ER-DataTypes.SM-DeliveryFailureCauseWithDiagnostic"
)
