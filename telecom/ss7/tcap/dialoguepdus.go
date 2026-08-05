// Code generated from ASN.1 module "DialoguePDUs". DO NOT EDIT.

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

// DialogueAsId returns the OID value for dialogue-as-id.
func DialogueAsId() runtime.ObjectIdentifier { return runtime.ObjectIdentifier{0, 0, 17, 773, 1, 1, 1} }

// DialoguePDU choice constants.
const (
	DialoguePDUChoiceDialogueRequest  = 1
	DialoguePDUChoiceDialogueResponse = 2
	DialoguePDUChoiceDialogueAbort    = 3
)

// DialoguePDU represents the ASN.1 CHOICE type DialoguePDU.
type DialoguePDU struct {
	Choice           int
	DialogueRequest  *AARQApdu `json:"DialogueRequest,omitempty"`
	DialogueResponse *AAREApdu `json:"DialogueResponse,omitempty"`
	DialogueAbort    *ABRTApdu `json:"DialogueAbort,omitempty"`
}

// NewDialoguePDUDialogueRequest creates a DialoguePDU with the dialogueRequest alternative.
func NewDialoguePDUDialogueRequest(v AARQApdu) DialoguePDU {
	return DialoguePDU{
		Choice:          DialoguePDUChoiceDialogueRequest,
		DialogueRequest: &v,
	}
}

// NewDialoguePDUDialogueResponse creates a DialoguePDU with the dialogueResponse alternative.
func NewDialoguePDUDialogueResponse(v AAREApdu) DialoguePDU {
	return DialoguePDU{
		Choice:           DialoguePDUChoiceDialogueResponse,
		DialogueResponse: &v,
	}
}

// NewDialoguePDUDialogueAbort creates a DialoguePDU with the dialogueAbort alternative.
func NewDialoguePDUDialogueAbort(v ABRTApdu) DialoguePDU {
	return DialoguePDU{
		Choice:        DialoguePDUChoiceDialogueAbort,
		DialogueAbort: &v,
	}
}

// AARQApdu represents the ASN.1 type AARQ-apdu (SEQUENCE).
type AARQApdu struct {
	ProtocolVersion        *runtime.BitString       `asn1:"tag:0,context,implicit,optional" json:"ProtocolVersion,omitempty"`
	ApplicationContextName runtime.ObjectIdentifier `asn1:"tag:1,context,explicit"`
	UserInformation        AARQApduUserInformation  `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_  bool                     `asn1:"-" json:"-"`
}

// AAREApdu represents the ASN.1 type AARE-apdu (SEQUENCE).
type AAREApdu struct {
	ProtocolVersion        *runtime.BitString        `asn1:"tag:0,context,implicit,optional" json:"ProtocolVersion,omitempty"`
	ApplicationContextName runtime.ObjectIdentifier  `asn1:"tag:1,context,explicit"`
	Result                 AssociateResult           `asn1:"tag:2,context,explicit"`
	ResultSourceDiagnostic AssociateSourceDiagnostic `asn1:"tag:3,context,explicit"`
	UserInformation        AAREApduUserInformation   `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_  bool                      `asn1:"-" json:"-"`
}

// RLRQApdu represents the ASN.1 type RLRQ-apdu (SEQUENCE).
type RLRQApdu struct {
	Reason                *ReleaseRequestReason   `asn1:"tag:0,context,implicit,optional" json:"Reason,omitempty"`
	UserInformation       RLRQApduUserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_ bool                    `asn1:"-" json:"-"`
}

// RLREApdu represents the ASN.1 type RLRE-apdu (SEQUENCE).
type RLREApdu struct {
	Reason                *ReleaseResponseReason  `asn1:"tag:0,context,implicit,optional" json:"Reason,omitempty"`
	UserInformation       RLREApduUserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_ bool                    `asn1:"-" json:"-"`
}

// ABRTApdu represents the ASN.1 type ABRT-apdu (SEQUENCE).
type ABRTApdu struct {
	AbortSource           ABRTSource              `asn1:"tag:0,context,implicit"`
	UserInformation       ABRTApduUserInformation `asn1:"tag:30,context,implicit,optional" json:"UserInformation,omitempty"`
	UserInformationIndef_ bool                    `asn1:"-" json:"-"`
}

// ABRTSource represents the ASN.1 INTEGER type ABRT-source with named numbers.
type ABRTSource int64

const (
	ABRTSourceDialogueServiceUser     ABRTSource = 0
	ABRTSourceDialogueServiceProvider ABRTSource = 1
)

func (v ABRTSource) String() string {
	switch v {
	case ABRTSourceDialogueServiceUser:
		return "dialogue-service-user"
	case ABRTSourceDialogueServiceProvider:
		return "dialogue-service-provider"
	default:
		return "unknown"
	}
}

// AssociateResult represents the ASN.1 INTEGER type Associate-result with named numbers.
type AssociateResult int64

const (
	AssociateResultAccepted        AssociateResult = 0
	AssociateResultRejectPermanent AssociateResult = 1
)

func (v AssociateResult) String() string {
	switch v {
	case AssociateResultAccepted:
		return "accepted"
	case AssociateResultRejectPermanent:
		return "reject-permanent"
	default:
		return "unknown"
	}
}

// AssociateSourceDiagnostic choice constants.
const (
	AssociateSourceDiagnosticChoiceDialogueServiceUser     = 1
	AssociateSourceDiagnosticChoiceDialogueServiceProvider = 2
)

// AssociateSourceDiagnostic represents the ASN.1 CHOICE type Associate-source-diagnostic.
type AssociateSourceDiagnostic struct {
	Choice                  int
	DialogueServiceUser     *int64 `json:"DialogueServiceUser,omitempty"`
	DialogueServiceProvider *int64 `json:"DialogueServiceProvider,omitempty"`
}

// NewAssociateSourceDiagnosticDialogueServiceUser creates a Associate-source-diagnostic with the dialogue-service-user alternative.
func NewAssociateSourceDiagnosticDialogueServiceUser(v int64) AssociateSourceDiagnostic {
	return AssociateSourceDiagnostic{
		Choice:              AssociateSourceDiagnosticChoiceDialogueServiceUser,
		DialogueServiceUser: &v,
	}
}

// NewAssociateSourceDiagnosticDialogueServiceProvider creates a Associate-source-diagnostic with the dialogue-service-provider alternative.
func NewAssociateSourceDiagnosticDialogueServiceProvider(v int64) AssociateSourceDiagnostic {
	return AssociateSourceDiagnostic{
		Choice:                  AssociateSourceDiagnosticChoiceDialogueServiceProvider,
		DialogueServiceProvider: &v,
	}
}

// ReleaseRequestReason represents the ASN.1 INTEGER type Release-request-reason with named numbers.
type ReleaseRequestReason int64

const (
	ReleaseRequestReasonNormal      ReleaseRequestReason = 0
	ReleaseRequestReasonUrgent      ReleaseRequestReason = 1
	ReleaseRequestReasonUserDefined ReleaseRequestReason = 30
)

func (v ReleaseRequestReason) String() string {
	switch v {
	case ReleaseRequestReasonNormal:
		return "normal"
	case ReleaseRequestReasonUrgent:
		return "urgent"
	case ReleaseRequestReasonUserDefined:
		return "user-defined"
	default:
		return "unknown"
	}
}

// ReleaseResponseReason represents the ASN.1 INTEGER type Release-response-reason with named numbers.
type ReleaseResponseReason int64

const (
	ReleaseResponseReasonNormal      ReleaseResponseReason = 0
	ReleaseResponseReasonNotFinished ReleaseResponseReason = 1
	ReleaseResponseReasonUserDefined ReleaseResponseReason = 30
)

func (v ReleaseResponseReason) String() string {
	switch v {
	case ReleaseResponseReasonNormal:
		return "normal"
	case ReleaseResponseReasonNotFinished:
		return "not-finished"
	case ReleaseResponseReasonUserDefined:
		return "user-defined"
	default:
		return "unknown"
	}
}

// AARQApduUserInformation represents the ASN.1 type AARQ-apdu-user-information (SEQUENCE_OF).
type AARQApduUserInformation = []runtime.RawValue

// AAREApduUserInformation represents the ASN.1 type AARE-apdu-user-information (SEQUENCE_OF).
type AAREApduUserInformation = []runtime.RawValue

// RLRQApduUserInformation represents the ASN.1 type RLRQ-apdu-user-information (SEQUENCE_OF).
type RLRQApduUserInformation = []runtime.RawValue

// RLREApduUserInformation represents the ASN.1 type RLRE-apdu-user-information (SEQUENCE_OF).
type RLREApduUserInformation = []runtime.RawValue

// ABRTApduUserInformation represents the ASN.1 type ABRT-apdu-user-information (SEQUENCE_OF).
type ABRTApduUserInformation = []runtime.RawValue

// MarshalBER encodes DialoguePDU to BER format.
func (v *DialoguePDU) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case DialoguePDUChoiceDialogueRequest:
		if v.DialogueRequest == nil {
			return nil, fmt.Errorf("choice DialoguePDU: dialogueRequest is nil")
		}
		enc_0, err := v.DialogueRequest.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding dialogueRequest: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 0, true, enc_0)
		return enc_0, nil
	case DialoguePDUChoiceDialogueResponse:
		if v.DialogueResponse == nil {
			return nil, fmt.Errorf("choice DialoguePDU: dialogueResponse is nil")
		}
		enc_1, err := v.DialogueResponse.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding dialogueResponse: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 1, true, enc_1)
		return enc_1, nil
	case DialoguePDUChoiceDialogueAbort:
		if v.DialogueAbort == nil {
			return nil, fmt.Errorf("choice DialoguePDU: dialogueAbort is nil")
		}
		enc_2, err := v.DialogueAbort.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding dialogueAbort: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassApplication, 4, true, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for DialoguePDU", v.Choice)
	}
}

// MarshalDER encodes DialoguePDU to DER format.
func (v *DialoguePDU) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes DialoguePDU from BER/DER format.
func (v *DialoguePDU) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for DialoguePDU CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for DialoguePDU: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding DialoguePDU CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "DialoguePDU", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassApplication && peekTag.Number == 0 {
		v.Choice = DialoguePDUChoiceDialogueRequest
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogueRequest: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AARQApdu
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding dialogueRequest: %w", unmErr)
		}
		v.DialogueRequest = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 1 {
		v.Choice = DialoguePDUChoiceDialogueResponse
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogueResponse: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AAREApdu
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding dialogueResponse: %w", unmErr)
		}
		v.DialogueResponse = &dec
	} else if peekTag.Class == tag.ClassApplication && peekTag.Number == 4 {
		v.Choice = DialoguePDUChoiceDialogueAbort
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogueAbort: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ABRTApdu
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding dialogueAbort: %w", unmErr)
		}
		v.DialogueAbort = &dec
	} else {
		return fmt.Errorf("unknown tag %s for DialoguePDU CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes AARQApdu to BER format.
func (v *AARQApdu) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ProtocolVersion != nil {
		enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, (8-(v.ProtocolVersion.BitLength%8))%8)
		enc_protocolversion = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_protocolversion)
		children = append(children, enc_protocolversion...)
	}
	enc_applicationcontextname := ber.EncodeObjectIdentifier([]uint64(v.ApplicationContextName))
	enc_applicationcontextname = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
	children = append(children, enc_applicationcontextname...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERAARQApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_userinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
		} else {
			enc_userinformation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, true, enc_userinformation)
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 0, Constructed: true}, children), nil
}

// MarshalDER encodes AARQApdu to DER format.
func (v *AARQApdu) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AARQApdu from BER/DER format.
func (v *AARQApdu) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AARQApdu: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 0 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AARQApdu: %w: expected tag [APPLICATION 0], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AARQApdu", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocol-version
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_protocolversion, rawVal_protocolversion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding protocol-version: %w", err)
				}
				bsBytes_protocolversion, bsUnused_protocolversion, bsErr := ber.DecodeBitStringValue(rawVal_protocolversion)
				if bsErr != nil {
					return fmt.Errorf("decoding protocol-version: %w", bsErr)
				}
				tmp_protocolversion := runtime.BitString{Bytes: bsBytes_protocolversion, BitLength: len(bsBytes_protocolversion)*8 - bsUnused_protocolversion}
				v.ProtocolVersion = &tmp_protocolversion
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
	_, n_applicationcontextname, innerData_applicationcontextname, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding application-context-name: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	val_applicationcontextname, _, oidErr := ber.DecodeObjectIdentifier(innerData_applicationcontextname)
	if oidErr != nil {
		return fmt.Errorf("decoding application-context-name: %w", oidErr)
	}
	v.ApplicationContextName = runtime.ObjectIdentifier(val_applicationcontextname)
	offset += n_applicationcontextname
	// Decode user-information
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				_, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				reconstructed_userinformation := ber.EncodeSequence(rawVal_userinformation)
				dec_userinformation, unmErr := UnmarshalBERAARQApduUserInformation(reconstructed_userinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				offset += n_userinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AARQApdu", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AAREApdu to BER format.
func (v *AAREApdu) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ProtocolVersion != nil {
		enc_protocolversion := ber.EncodeBitString(v.ProtocolVersion.Bytes, (8-(v.ProtocolVersion.BitLength%8))%8)
		enc_protocolversion = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_protocolversion)
		children = append(children, enc_protocolversion...)
	}
	enc_applicationcontextname := ber.EncodeObjectIdentifier([]uint64(v.ApplicationContextName))
	enc_applicationcontextname = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_applicationcontextname)
	children = append(children, enc_applicationcontextname...)
	enc_result := ber.EncodeInteger(int64(v.Result))
	enc_result = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_result)
	children = append(children, enc_result...)
	enc_resultsourcediagnostic, err := v.ResultSourceDiagnostic.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding result-source-diagnostic: %w", err)
	}
	enc_resultsourcediagnostic = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_resultsourcediagnostic)
	children = append(children, enc_resultsourcediagnostic...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERAAREApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_userinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
		} else {
			enc_userinformation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, true, enc_userinformation)
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 1, Constructed: true}, children), nil
}

// MarshalDER encodes AAREApdu to DER format.
func (v *AAREApdu) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AAREApdu from BER/DER format.
func (v *AAREApdu) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding AAREApdu: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 1 || !decodedTag.Constructed {
		return fmt.Errorf("decoding AAREApdu: %w: expected tag [APPLICATION 1], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AAREApdu", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocol-version
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_protocolversion, rawVal_protocolversion, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding protocol-version: %w", err)
				}
				bsBytes_protocolversion, bsUnused_protocolversion, bsErr := ber.DecodeBitStringValue(rawVal_protocolversion)
				if bsErr != nil {
					return fmt.Errorf("decoding protocol-version: %w", bsErr)
				}
				tmp_protocolversion := runtime.BitString{Bytes: bsBytes_protocolversion, BitLength: len(bsBytes_protocolversion)*8 - bsUnused_protocolversion}
				v.ProtocolVersion = &tmp_protocolversion
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
	_, n_applicationcontextname, innerData_applicationcontextname, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding application-context-name: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	val_applicationcontextname, _, oidErr := ber.DecodeObjectIdentifier(innerData_applicationcontextname)
	if oidErr != nil {
		return fmt.Errorf("decoding application-context-name: %w", oidErr)
	}
	v.ApplicationContextName = runtime.ObjectIdentifier(val_applicationcontextname)
	offset += n_applicationcontextname
	// Decode result
	if offset >= len(content) {
		return fmt.Errorf("missing required field result")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for result, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	_, n_result, innerData_result, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding result: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	val_result, _, err := ber.DecodeInteger(innerData_result)
	if err != nil {
		return fmt.Errorf("decoding result: %w", err)
	}
	v.Result = AssociateResult(val_result)
	offset += n_result
	// Decode result-source-diagnostic
	if offset >= len(content) {
		return fmt.Errorf("missing required field result-source-diagnostic")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for result-source-diagnostic, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	_, n_resultsourcediagnostic, innerData_resultsourcediagnostic, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding result-source-diagnostic: %w", err)
	}
	// Decode inner value from explicit tag wrapper
	if unmErr := v.ResultSourceDiagnostic.UnmarshalBER(innerData_resultsourcediagnostic); unmErr != nil {
		return fmt.Errorf("decoding result-source-diagnostic: %w", unmErr)
	}
	offset += n_resultsourcediagnostic
	// Decode user-information
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				_, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				reconstructed_userinformation := ber.EncodeSequence(rawVal_userinformation)
				dec_userinformation, unmErr := UnmarshalBERAAREApduUserInformation(reconstructed_userinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				offset += n_userinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AAREApdu", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RLRQApdu to BER format.
func (v *RLRQApdu) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Reason != nil {
		enc_reason := ber.EncodeInteger(int64(*v.Reason))
		enc_reason = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_reason)
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERRLRQApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_userinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
		} else {
			enc_userinformation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, true, enc_userinformation)
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 2, Constructed: true}, children), nil
}

// MarshalDER encodes RLRQApdu to DER format.
func (v *RLRQApdu) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RLRQApdu from BER/DER format.
func (v *RLRQApdu) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding RLRQApdu: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 2 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RLRQApdu: %w: expected tag [APPLICATION 2], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RLRQApdu", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_reason, rawVal_reason, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reason: %w", err)
				}
				decVal_reason, intErr := ber.DecodeIntegerValue(rawVal_reason)
				if intErr != nil {
					return fmt.Errorf("decoding reason: %w", intErr)
				}
				tmp_reason := ReleaseRequestReason(decVal_reason)
				v.Reason = &tmp_reason
				offset += n_reason
			}
		}
	}
	// Decode user-information
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				_, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				reconstructed_userinformation := ber.EncodeSequence(rawVal_userinformation)
				dec_userinformation, unmErr := UnmarshalBERRLRQApduUserInformation(reconstructed_userinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				offset += n_userinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "RLRQApdu", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RLREApdu to BER format.
func (v *RLREApdu) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Reason != nil {
		enc_reason := ber.EncodeInteger(int64(*v.Reason))
		enc_reason = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_reason)
		children = append(children, enc_reason...)
	}
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERRLREApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_userinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
		} else {
			enc_userinformation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, true, enc_userinformation)
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 3, Constructed: true}, children), nil
}

// MarshalDER encodes RLREApdu to DER format.
func (v *RLREApdu) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RLREApdu from BER/DER format.
func (v *RLREApdu) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding RLREApdu: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 3 || !decodedTag.Constructed {
		return fmt.Errorf("decoding RLREApdu: %w: expected tag [APPLICATION 3], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RLREApdu", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reason
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_reason, rawVal_reason, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding reason: %w", err)
				}
				decVal_reason, intErr := ber.DecodeIntegerValue(rawVal_reason)
				if intErr != nil {
					return fmt.Errorf("decoding reason: %w", intErr)
				}
				tmp_reason := ReleaseResponseReason(decVal_reason)
				v.Reason = &tmp_reason
				offset += n_reason
			}
		}
	}
	// Decode user-information
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				_, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				reconstructed_userinformation := ber.EncodeSequence(rawVal_userinformation)
				dec_userinformation, unmErr := UnmarshalBERRLREApduUserInformation(reconstructed_userinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				offset += n_userinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "RLREApdu", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes ABRTApdu to BER format.
func (v *ABRTApdu) MarshalBER() ([]byte, error) {
	var children []byte
	enc_abortsource := ber.EncodeInteger(int64(v.AbortSource))
	enc_abortsource = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_abortsource)
	children = append(children, enc_abortsource...)
	if v.UserInformation != nil {
		enc_userinformation, err := MarshalBERABRTApduUserInformation(v.UserInformation)
		if err != nil {
			return nil, fmt.Errorf("encoding user-information: %w", err)
		}
		if v.UserInformationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_userinformation)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_userinformation = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 30}, seqContent_)
		} else {
			enc_userinformation = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 30, true, enc_userinformation)
		}
		children = append(children, enc_userinformation...)
	}
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassApplication, Number: 4, Constructed: true}, children), nil
}

// MarshalDER encodes ABRTApdu to DER format.
func (v *ABRTApdu) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ABRTApdu from BER/DER format.
func (v *ABRTApdu) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ABRTApdu: %w", err)
	}
	if decodedTag.Class != tag.ClassApplication || decodedTag.Number != 4 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ABRTApdu: %w: expected tag [APPLICATION 4], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ABRTApdu", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode abort-source
	if offset >= len(content) {
		return fmt.Errorf("missing required field abort-source")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for abort-source, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	_, n_abortsource, rawVal_abortsource, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding abort-source: %w", err)
	}
	decVal_abortsource, intErr := ber.DecodeIntegerValue(rawVal_abortsource)
	if intErr != nil {
		return fmt.Errorf("decoding abort-source: %w", intErr)
	}
	v.AbortSource = ABRTSource(decVal_abortsource)
	offset += n_abortsource
	// Decode user-information
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 30 {
				_, n_userinformation, rawVal_userinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding user-information: %w", err)
				}
				reconstructed_userinformation := ber.EncodeSequence(rawVal_userinformation)
				dec_userinformation, unmErr := UnmarshalBERABRTApduUserInformation(reconstructed_userinformation)
				if unmErr != nil {
					return fmt.Errorf("decoding user-information: %w", unmErr)
				}
				v.UserInformation = dec_userinformation
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.UserInformationIndef_ = true
					}
				}
				offset += n_userinformation
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ABRTApdu", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AssociateSourceDiagnostic to BER format.
func (v *AssociateSourceDiagnostic) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case AssociateSourceDiagnosticChoiceDialogueServiceUser:
		if v.DialogueServiceUser == nil {
			return nil, fmt.Errorf("choice AssociateSourceDiagnostic: dialogue-service-user is nil")
		}
		enc_0 := ber.EncodeInteger(int64(*v.DialogueServiceUser))
		enc_0 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		return enc_0, nil
	case AssociateSourceDiagnosticChoiceDialogueServiceProvider:
		if v.DialogueServiceProvider == nil {
			return nil, fmt.Errorf("choice AssociateSourceDiagnostic: dialogue-service-provider is nil")
		}
		enc_1 := ber.EncodeInteger(int64(*v.DialogueServiceProvider))
		enc_1 = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for AssociateSourceDiagnostic", v.Choice)
	}
}

// MarshalDER encodes AssociateSourceDiagnostic to DER format.
func (v *AssociateSourceDiagnostic) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes AssociateSourceDiagnostic from BER/DER format.
func (v *AssociateSourceDiagnostic) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for AssociateSourceDiagnostic CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for AssociateSourceDiagnostic: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding AssociateSourceDiagnostic CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "AssociateSourceDiagnostic", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = AssociateSourceDiagnosticChoiceDialogueServiceUser
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogue-service-user: %w", tlvErr)
		}
		decVal, _, intErr := ber.DecodeInteger(innerData)
		if intErr != nil {
			return fmt.Errorf("decoding dialogue-service-user: %w", intErr)
		}
		v.DialogueServiceUser = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = AssociateSourceDiagnosticChoiceDialogueServiceProvider
		_, _, innerData, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dialogue-service-provider: %w", tlvErr)
		}
		decVal, _, intErr := ber.DecodeInteger(innerData)
		if intErr != nil {
			return fmt.Errorf("decoding dialogue-service-provider: %w", intErr)
		}
		v.DialogueServiceProvider = &decVal
	} else {
		return fmt.Errorf("unknown tag %s for AssociateSourceDiagnostic CHOICE", peekTag)
	}
	return nil
}

// MarshalBERAARQApduUserInformation encodes a AARQApduUserInformation list to BER.
func MarshalBERAARQApduUserInformation(list AARQApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERAARQApduUserInformation decodes a AARQApduUserInformation list from BER.
func UnmarshalBERAARQApduUserInformation(data []byte) (AARQApduUserInformation, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AARQApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AARQApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result AARQApduUserInformation
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: content[offset : offset+n]})
		offset += n
	}
	return result, nil
}

// MarshalBERAAREApduUserInformation encodes a AAREApduUserInformation list to BER.
func MarshalBERAAREApduUserInformation(list AAREApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERAAREApduUserInformation decodes a AAREApduUserInformation list from BER.
func UnmarshalBERAAREApduUserInformation(data []byte) (AAREApduUserInformation, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding AAREApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "AAREApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result AAREApduUserInformation
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: content[offset : offset+n]})
		offset += n
	}
	return result, nil
}

// MarshalBERRLRQApduUserInformation encodes a RLRQApduUserInformation list to BER.
func MarshalBERRLRQApduUserInformation(list RLRQApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERRLRQApduUserInformation decodes a RLRQApduUserInformation list from BER.
func UnmarshalBERRLRQApduUserInformation(data []byte) (RLRQApduUserInformation, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RLRQApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RLRQApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result RLRQApduUserInformation
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: content[offset : offset+n]})
		offset += n
	}
	return result, nil
}

// MarshalBERRLREApduUserInformation encodes a RLREApduUserInformation list to BER.
func MarshalBERRLREApduUserInformation(list RLREApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERRLREApduUserInformation decodes a RLREApduUserInformation list from BER.
func UnmarshalBERRLREApduUserInformation(data []byte) (RLREApduUserInformation, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding RLREApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RLREApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result RLREApduUserInformation
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: content[offset : offset+n]})
		offset += n
	}
	return result, nil
}

// MarshalBERABRTApduUserInformation encodes a ABRTApduUserInformation list to BER.
func MarshalBERABRTApduUserInformation(list ABRTApduUserInformation) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, elem.Bytes...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERABRTApduUserInformation decodes a ABRTApduUserInformation list from BER.
func UnmarshalBERABRTApduUserInformation(data []byte) (ABRTApduUserInformation, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ABRTApduUserInformation: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ABRTApduUserInformation", Cause: ber.ErrExtraData}
	}
	var result ABRTApduUserInformation
	offset := 0
	for offset < len(content) {
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element: %w", tlvErr)
		}
		result = append(result, runtime.RawValue{Bytes: content[offset : offset+n]})
		offset += n
	}
	return result, nil
}
