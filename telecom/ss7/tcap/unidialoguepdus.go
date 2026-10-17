// Code generated from ASN.1 module "UnidialoguePDUs". DO NOT EDIT.

package tcap

import (
	"fmt"

	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/tcap/runtime/tag"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

// UniDialogueAsId returns the OID value for uniDialogue-as-id.
func UniDialogueAsId() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x00\x11\x86\x05\x01\x02\x01")
}

// UniDialoguePDU choice constants.
const (
	UniDialoguePDUChoiceUnidialoguePDU = 1
)

// UniDialoguePDU represents the ASN.1 CHOICE type UniDialoguePDU.
type UniDialoguePDU struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	UnidialoguePDU *AUDTApdu       `json:"UnidialoguePDU,omitempty"`
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
	ProtocolVersion            *runtime.BitString       `asn1:"tag:0,context,implicit,optional" json:"ProtocolVersion,omitempty"`
	ApplicationContextName     runtime.ObjectIdentifier `asn1:"tag:1,context,explicit"`
	UserInformation            *UserInformation         `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	berUserInformationIndef_   bool                     `asn1:"-" json:"-"`
	berReplayNode_             *ber.ReplayNode          `asn1:"-" json:"-"`
	berProtocolVersionPresent_ bool
}

const (
	// AUDTApduProtocolVersionVersion1 is position 0 of ASN.1 named bit version1 of AUDT-apdu.protocol-version (ITU-T X.680 (02/2021) §22).
	AUDTApduProtocolVersionVersion1 = 0
)

// MarshalBER encodes UniDialoguePDU to BER format.
func (v *UniDialoguePDU) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil,

			err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: UniDialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) && (v.Choice == UniDialoguePDUChoiceUnidialoguePDU) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *UniDialoguePDU) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil,

			err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: UniDialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	switch v.Choice {
	case UniDialoguePDUChoiceUnidialoguePDU:
		if v.UnidialoguePDU == nil {
			return nil, fmt.Errorf("%w: choice UniDialoguePDU: unidialoguePDU is nil", ber.ErrInvalidValue)
		}
		_, err := v.UnidialoguePDU.appendBERLinear(encoder, ber.ChildGeneratedEncodeOptions(opts, "unidialoguePDU")...)
		if err != nil {
			return nil, qualifyBERError(err, "unidialoguePDU", "encoding", true)
		}
		return nil, nil
	default:
		encoded, err := v.marshalBER(opts...)
		if err != nil {
			return nil, err
		}
		encoder.Append(encoded)
		return nil, nil
	}
}
func (v *UniDialoguePDU) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil,

			err
	}

	switch v.Choice {
	case UniDialoguePDUChoiceUnidialoguePDU:
		if v.UnidialoguePDU == nil {
			return nil, fmt.Errorf("%w: choice UniDialoguePDU: unidialoguePDU is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.UnidialoguePDU.MarshalBER(ber.ChildEncodeOptions(opts, "unidialoguePDU")...)
		if err != nil {
			return nil, qualifyBERError(err, "unidialoguePDU", "encoding", false)
		}
		return enc_0, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for UniDialoguePDU", v.Choice)
	}
}

// MarshalDER encodes UniDialoguePDU to DER format.
func (v *UniDialoguePDU) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil,

			err
	}
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: UniDialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	if v.Choice == UniDialoguePDUChoiceUnidialoguePDU {
		encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendDERLinear(encoder)
			return appendErr
		})
		if err != nil {
			return nil, err
		}
		return encoded, nil
	}
	switch v.Choice {
	case UniDialoguePDUChoiceUnidialoguePDU:
		if v.UnidialoguePDU == nil {
			return nil, fmt.Errorf("%w: choice UniDialoguePDU: unidialoguePDU is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.UnidialoguePDU.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "unidialoguePDU", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "unidialoguePDU", "encoding", true)
		}
		return enc_der_0, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case UniDialoguePDUChoiceUnidialoguePDU:
			return nil, qualifyBERError(err, "unidialoguePDU", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding UniDialoguePDU as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *UniDialoguePDU) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if err := v.validateTCAPChoice(); err != nil {
		return nil,

			err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: UniDialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case UniDialoguePDUChoiceUnidialoguePDU:
		if v.UnidialoguePDU == nil {
			return nil, fmt.Errorf("%w: choice UniDialoguePDU: unidialoguePDU is nil", ber.ErrInvalidValue)
		}
		_, err := v.UnidialoguePDU.appendDERLinear(encoder)
		if err != nil {
			return nil, qualifyBERError(err, "unidialoguePDU", "encoding", true)
		}
		return nil, nil
	default:
		encoded, err := v.MarshalDER()
		if err != nil {
			return nil, err
		}
		encoder.Append(encoded)
		return nil, nil
	}
}

// UnmarshalBER decodes UniDialoguePDU from BER/DER format.
func (destination *UniDialoguePDU) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil UniDialoguePDU destination")
	}
	var next UniDialoguePDU
	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *UniDialoguePDU, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe UniDialoguePDU
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
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
		return fmt.Errorf("%s: %w", "decoding UniDialoguePDU CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "UniDialoguePDU", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassApplication && peekTag.Number == 0) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "UniDialoguePDU.unidialoguePDU", "decoding", false)
	}
	if peekTag.Class == tag.ClassApplication && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = UniDialoguePDUChoiceUnidialoguePDU
		ber.MarkPreflightTarget(opts, "unidialoguePDU", choiceData)
		var dec AUDTApdu
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "unidialoguePDU")...); unmErr != nil {
			return qualifyBERError(unmErr, "unidialoguePDU", "decoding", false)
		}
		v.UnidialoguePDU = &dec
	} else {
		return fmt.Errorf("unknown tag %s for UniDialoguePDU CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AUDTApdu to BER format.
func (v *AUDTApdu) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	linearOptions_ := len(opts) == 0
	opts, commitReports := ber.StageGeneratedEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: AUDTApdu receiver is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var replayErr error
	opts, replayErr = ber.PrepareBERReplay(tcapReplayNode(v, v.berReplayNode_), opts, func(mode ber.EncodeOption) ([]byte, error) { return v.MarshalBER([]ber.EncodeOption{mode}...) }, v)
	if replayErr != nil {
		return nil, replayErr
	}
	if replayBytes, ok := ber.PreparedBERReplay(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		return replayBytes, nil
	}
	var encoded []byte
	var err error
	if linearOptions_ && ber.CanUseLinearBEREncode(opts) {
		encoded, err = ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
			_, appendErr := v.appendBERLinear(encoder, opts...)
			return appendErr
		})
	} else {
		encoded, err = v.marshalBER(opts...)
	}
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBERNode(encoded, tcapReplayNode(v, v.berReplayNode_), opts), nil
}
func (v *AUDTApdu) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	var children []byte
	if v.ProtocolVersion != nil &&
		!v.ProtocolVersion.EqualBits("\x80", 1, true) {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := encodeTCAPBitString(v.ProtocolVersion.Bytes, ber.UnusedBitCount(v.ProtocolVersion.BitLength))
		if encodeErr_enc_protocolversion != nil {
			return nil, qualifyBERError(encodeErr_enc_protocolversion, "protocol-version", "encoding", false)
		}
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, qualifyBERError(tagErr_enc_protocolversion, "protocol-version", "encoding", false)
		}
		enc_protocolversion = retagged_enc_protocolversion
		children = append(children, enc_protocolversion...)
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked(v.ApplicationContextName)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "application-context-name", "encoding", false)
	}
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "application-context-name", "encoding", false)
		}
	}
	children = append(children, enc_applicationcontextname...)
	if v.UserInformation != nil {
		enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "user-information"))...)
		if err != nil {
			return nil, qualifyBERError(err, "user-information", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berUserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "user-information", "encoding", false)
				}
			}
		} else {
			retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
			if tagErr_enc_userinformation != nil {
				return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", false)
			}
			enc_userinformation = retagged_enc_userinformation
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_userinformation)
		children = append(children, enc_userinformation...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 0, Constructed: true}, children)
}
func (v *AUDTApdu) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AUDTApdu receiver is nil", ber.ErrInvalidValue)
	}
	if replay, ok := ber.ReplayGeneratedBERNode(tcapReplayNode(v, v.berReplayNode_), opts); ok {
		encoder.Append(replay)
		return nil, nil
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 0})
	if v.ProtocolVersion != nil &&
		!v.ProtocolVersion.EqualBits("\x80", 1, true) {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := encodeTCAPBitString(v.ProtocolVersion.Bytes, ber.UnusedBitCount(v.ProtocolVersion.BitLength))
		if encodeErr_enc_protocolversion != nil {
			return nil, qualifyBERError(encodeErr_enc_protocolversion, "protocol-version", "encoding", true)
		}
		retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
		if tagErr_enc_protocolversion != nil {
			return nil, qualifyBERError(tagErr_enc_protocolversion, "protocol-version", "encoding", true)
		}
		enc_protocolversion = retagged_enc_protocolversion
		encoder.Append(enc_protocolversion)
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked(v.ApplicationContextName)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "application-context-name", "encoding", true)
	}
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "application-context-name", "encoding", true)
		}
	}
	encoder.Append(enc_applicationcontextname)
	if v.UserInformation != nil {
		if v.berUserInformationIndef_ && ber.BERGeneratedReplayEnabled(opts) {
			enc_userinformation, err := tcapMarshalBERUserInformation(v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
			if ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_ {
				// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
				_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_userinformation)
				if tlvErr_ != nil {
					return nil, tlvErr_
				}
				{
					var encodeErr error
					enc_userinformation, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
					if encodeErr != nil {
						return nil, qualifyBERError(encodeErr, "user-information", "encoding", true)
					}
				}
			} else {
				retagged_enc_userinformation, tagErr_enc_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, enc_userinformation)
				if tagErr_enc_userinformation != nil {
					return nil, qualifyBERError(tagErr_enc_userinformation, "user-information", "encoding", true)
				}
				enc_userinformation = retagged_enc_userinformation
			}
			encoder.Append(enc_userinformation)
		} else {
			{
				encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, ber.BERGeneratedReplayEnabled(opts) && v.berUserInformationIndef_)
				_, err := appendBERLinearUserInformation(encoder, v.UserInformation, ber.ChildGeneratedEncodeOptions(opts, "user-information")...)
				if err != nil {
					return nil, qualifyBERError(err, "user-information", "encoding", true)
				}
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// MarshalDER encodes AUDTApdu to DER format.
func (v *AUDTApdu) MarshalDER() ([]byte, error) {
	if err := v.validateTCAPStructure(); err != nil {
		return nil, err
	}

	if v == nil {
		return nil, fmt.Errorf("%w: AUDTApdu receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := ber.EncodeLinear(func(encoder *ber.LinearEncoder) error {
		_, appendErr := v.appendDERLinear(encoder)
		return appendErr
	})
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
func (v *AUDTApdu) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AUDTApdu receiver is nil", ber.ErrInvalidValue)
	}
	innerFrame_ := encoder.Begin(tag.Tag{Class: tag.ClassApplication, Number: 0})
	if v.ProtocolVersion != nil &&
		!v.ProtocolVersion.EqualBits("\x80", 1, true) {
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		if bitStringErr := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "protocol-version", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction
		if v.ProtocolVersion.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_protocolversion, encodeErr_enc_protocolversion := encodeTCAPNamedBitStringDER(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength)
		if encodeErr_enc_protocolversion != nil {
			return nil, qualifyBERError(encodeErr_enc_protocolversion, "protocol-version", "encoding", true)
		}
		if string(enc_protocolversion) != "\x03\x02\a\x80" {
			retagged_enc_protocolversion, tagErr_enc_protocolversion := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_protocolversion)
			if tagErr_enc_protocolversion != nil {
				return nil, qualifyBERError(tagErr_enc_protocolversion, "protocol-version", "encoding", true)
			}
			enc_protocolversion = retagged_enc_protocolversion
			encoder.Append(enc_protocolversion)
		}
	}
	enc_applicationcontextname, oidErr := ber.EncodeObjectIdentifierChecked(v.ApplicationContextName)
	if oidErr != nil {
		return nil, qualifyBERError(oidErr, "application-context-name", "encoding", true)
	}
	{
		var encodeErr error
		enc_applicationcontextname, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
		if encodeErr != nil {
			return nil, qualifyBERError(encodeErr, "application-context-name", "encoding", true)
		}
	}
	encoder.Append(enc_applicationcontextname)
	if v.UserInformation != nil {
		{
			encoder.OverrideNextTag(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, false)
			_, err := appendDERLinearUserInformation(encoder, v.UserInformation)
			if err != nil {
				return nil, qualifyBERError(err, "user-information", "encoding", true)
			}
		}
	}
	if err := encoder.End(innerFrame_); err != nil {
		return nil, err
	}
	return nil, nil
}

// UnmarshalBER decodes AUDTApdu from BER/DER format.
func (destination *AUDTApdu) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("nil AUDTApdu destination")
	}
	var next AUDTApdu

	v := &next
	defer func() {
		if returnErr == nil {
			*destination = *v
		}
	}()

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
			var probe AUDTApdu
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	*v = AUDTApdu{}
	defer func() {
		if returnErr != nil || !ber.BERNeedsPreservation(opts) {
			return
		}
		v.berReplayNode_ = ber.CaptureGeneratedBERReplay(data, opts)
		returnErr = ber.CompleteGeneratedBERDecode(opts, v, func(base *AUDTApdu, replayOpts ...ber.EncodeOption) ([]byte, error) {
			return base.MarshalBER(replayOpts...)
		})
	}()
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding AUDTApdu", qualifyBERError(err, "", "decoding", false))
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("%s: %w", "decoding AUDTApdu", qualifyBERError(fmt.Errorf("%w: expected tag [APPLICATION 0], got %s", ber.ErrInvalidTag, decodedTag), "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "protocol-version", content[offset:])
				decodedTag_protocolversion, n_protocolversion, rawVal_protocolversion, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "protocol-version", "decoding", false)
				}
				if decodedTag_protocolversion.Class != tag.ClassContextSpecific || decodedTag_protocolversion.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_protocolversion), "protocol-version", "decoding", false)
				}
				bsBytes_protocolversion, bsUnused_protocolversion, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_protocolversion.Constructed, rawVal_protocolversion, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "protocol-version", "decoding", false)
				}
				bsBitLength_protocolversion, bsLenErr_protocolversion := ber.BitStringBitLength(len(bsBytes_protocolversion), bsUnused_protocolversion)
				if bsLenErr_protocolversion != nil {
					return qualifyBERError(bsLenErr_protocolversion, "protocol-version", "decoding", false)
				}
				tmp_protocolversion := runtime.BitString{Bytes: bsBytes_protocolversion, BitLength: bsBitLength_protocolversion}
				v.ProtocolVersion = &tmp_protocolversion
				v.berProtocolVersionPresent_ = v.ProtocolVersion != nil

				if v.ProtocolVersion !=
					nil && v.
					ProtocolVersion.EqualBits("\x80", 1, true) {
					ber.MarkBERNonCanonical(opts)
				}

				if offset > len(content) || n_protocolversion < 0 || n_protocolversion > len(content[offset:]) {
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
	{
		ber.MarkPreflightTarget(opts, "application-context-name", content[offset:])
		decodedTag_applicationcontextname, n_applicationcontextname, innerData_applicationcontextname, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "application-context-name", "decoding", false)
		}
		if decodedTag_applicationcontextname.Class != tag.ClassContextSpecific || decodedTag_applicationcontextname.Number != 1 || decodedTag_applicationcontextname.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_applicationcontextname), "application-context-name", "decoding", false)
		}
		_, innerUsed_applicationcontextname, _, innerErr_applicationcontextname := ber.DecodeTLV(innerData_applicationcontextname, opts...)
		if innerErr_applicationcontextname != nil {
			return qualifyBERError(innerErr_applicationcontextname, "application-context-name", "decoding", false)
		}
		if innerUsed_applicationcontextname != len(innerData_applicationcontextname) {
			return qualifyBERError(ber.ErrExtraData, "application-context-name", "decoding", false)
		}
		// Decode inner value from explicit tag wrapper
		ber.MarkPreflightTarget(opts, "application-context-name", innerData_applicationcontextname)
		val_applicationcontextname, _, oidErr := ber.DecodeObjectIdentifier(innerData_applicationcontextname, opts...)
		if oidErr != nil {
			return qualifyBERError(oidErr, "application-context-name", "decoding", false)
		}
		v.ApplicationContextName = val_applicationcontextname
		if offset < 0 || offset >
			len(content) || n_applicationcontextname < 0 || n_applicationcontextname >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_applicationcontextname
	}
	// Decode user-information
	v.berUserInformationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				ber.MarkPreflightTarget(opts, "user-information", content[offset:])
				decodedTag_userinformation, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "user-information", "decoding", false)
				}
				if decodedTag_userinformation.Class != tag.ClassContextSpecific || decodedTag_userinformation.Number != 30 || decodedTag_userinformation.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_userinformation), "user-information", "decoding", false)
				}
				_ = rawVal_userinformation
				if offset < 0 || offset >
					len(content) || n_userinformation < 0 || n_userinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_userinformation, reconstructionErr_userinformation := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_userinformation])
				if reconstructionErr_userinformation != nil {
					return qualifyBERError(reconstructionErr_userinformation, "user-information", "decoding", false)
				}
				dec_userinformation, unmErr := tcapUnmarshalBERUserInformation(reconstructed_userinformation, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "user-information"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "user-information", "decoding", false)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berUserInformationIndef_ = true
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
func (v *UniDialoguePDU) validateTCAPChoice() error {
	if v == nil {
		return fmt.Errorf("nil UniDialoguePDU CHOICE")
	}
	count := 0
	if v.UnidialoguePDU != nil {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%w: CHOICE requires exactly one populated alternative", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case 1:
		if v.UnidialoguePDU == nil {
			return fmt.Errorf("%w: CHOICE discriminator disagrees with field", ber.ErrInvalidValue)
		}
	default:
		return fmt.Errorf("%w: invalid CHOICE discriminator", ber.ErrInvalidValue)
	}
	return nil
}
func (v *AUDTApdu) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if v.ProtocolVersion != nil {
		if err := ber.ValidateBitStringLength(v.ProtocolVersion.Bytes, v.ProtocolVersion.BitLength); err != nil {
			return err
		}
	}
	if err := validateTCAPStructureValue(v.UserInformation); err != nil {
		return err
	}
	return nil
}
func (v *AUDTApdu) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if v.berReplayNode_ != nil && (v.ProtocolVersion != nil) != v.berProtocolVersionPresent_ {
		return true
	}
	if hasTCAPPresenceEditValue(v.UserInformation) {
		return true
	}
	return false
}
func (v AUDTApdu) equalTCAPValue(other any) bool {
	right, ok := other.(AUDTApdu)
	if !ok {
		return false
	}
	_ = right
	if (v.ProtocolVersion == nil) != (right.ProtocolVersion == nil) {
		return false
	}
	if v.ProtocolVersion != nil && !equalTCAPValue(*v.ProtocolVersion, *right.ProtocolVersion) {
		return false
	}
	if !equalTCAPValue(v.ApplicationContextName, right.ApplicationContextName) {
		return false
	}
	if (v.UserInformation == nil) != (right.UserInformation == nil) {
		return false
	}
	if v.UserInformation != nil && !equalTCAPValue(*v.UserInformation, *right.UserInformation) {
		return false
	}
	return true
}
func (v *UniDialoguePDU) validateTCAPStructure() error {
	if v == nil {
		return nil
	}
	if err := v.validateTCAPChoice(); err != nil {
		return err
	}
	if err := validateTCAPStructureValue(v.UnidialoguePDU); err != nil {
		return err
	}
	return nil
}
func (v *UniDialoguePDU) hasTCAPPresenceEdit() bool {
	if v == nil {
		return false
	}
	if hasTCAPPresenceEditValue(v.UnidialoguePDU) {
		return true
	}
	return false
}
func (v UniDialoguePDU) equalTCAPValue(other any) bool {
	right, ok := other.(UniDialoguePDU)
	if !ok {
		return false
	}
	_ = right
	if !equalTCAPValue(v.Choice, right.Choice) {
		return false
	}
	if (v.UnidialoguePDU == nil) != (right.UnidialoguePDU == nil) {
		return false
	}
	if v.UnidialoguePDU != nil && !equalTCAPValue(*v.UnidialoguePDU, *right.UnidialoguePDU) {
		return false
	}
	return true
}
