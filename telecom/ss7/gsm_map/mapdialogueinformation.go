// Code generated from ASN.1 module "MAP-DialogueInformation". DO NOT EDIT.

package gsm_map

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

// MapDialogueAS returns the OID value for map-DialogueAS.
func MapDialogueAS() runtime.ObjectIdentifier {
	return runtime.MustObjectIdentifierFromEncoded("\x04\x00\x00\x01\x01\x01\x01")
}

// MAPDialoguePDU choice constants.
const (
	MAPDialoguePDUChoiceMapOpen          = 1
	MAPDialoguePDUChoiceMapAccept        = 2
	MAPDialoguePDUChoiceMapClose         = 3
	MAPDialoguePDUChoiceMapRefuse        = 4
	MAPDialoguePDUChoiceMapUserAbort     = 5
	MAPDialoguePDUChoiceMapProviderAbort = 6
)

// MAPDialoguePDU represents the ASN.1 CHOICE type MAP-DialoguePDU.
type MAPDialoguePDU struct {
	Choice           int
	berReplayNode_   *ber.ReplayNode       `json:"-"`
	MapOpen          *MAPOpenInfo          `json:"MapOpen,omitempty"`
	MapAccept        *MAPAcceptInfo        `json:"MapAccept,omitempty"`
	MapClose         *MAPCloseInfo         `json:"MapClose,omitempty"`
	MapRefuse        *MAPRefuseInfo        `json:"MapRefuse,omitempty"`
	MapUserAbort     *MAPUserAbortInfo     `json:"MapUserAbort,omitempty"`
	MapProviderAbort *MAPProviderAbortInfo `json:"MapProviderAbort,omitempty"`
}

// NewMAPDialoguePDUMapOpen creates a MAPDialoguePDU with the map-open alternative.
func NewMAPDialoguePDUMapOpen(v MAPOpenInfo) MAPDialoguePDU {
	return MAPDialoguePDU{
		Choice:  MAPDialoguePDUChoiceMapOpen,
		MapOpen: &v,
	}
}

// NewMAPDialoguePDUMapAccept creates a MAPDialoguePDU with the map-accept alternative.
func NewMAPDialoguePDUMapAccept(v MAPAcceptInfo) MAPDialoguePDU {
	return MAPDialoguePDU{
		Choice:    MAPDialoguePDUChoiceMapAccept,
		MapAccept: &v,
	}
}

// NewMAPDialoguePDUMapClose creates a MAPDialoguePDU with the map-close alternative.
func NewMAPDialoguePDUMapClose(v MAPCloseInfo) MAPDialoguePDU {
	return MAPDialoguePDU{
		Choice:   MAPDialoguePDUChoiceMapClose,
		MapClose: &v,
	}
}

// NewMAPDialoguePDUMapRefuse creates a MAPDialoguePDU with the map-refuse alternative.
func NewMAPDialoguePDUMapRefuse(v MAPRefuseInfo) MAPDialoguePDU {
	return MAPDialoguePDU{
		Choice:    MAPDialoguePDUChoiceMapRefuse,
		MapRefuse: &v,
	}
}

// NewMAPDialoguePDUMapUserAbort creates a MAPDialoguePDU with the map-userAbort alternative.
func NewMAPDialoguePDUMapUserAbort(v MAPUserAbortInfo) MAPDialoguePDU {
	return MAPDialoguePDU{
		Choice:       MAPDialoguePDUChoiceMapUserAbort,
		MapUserAbort: &v,
	}
}

// NewMAPDialoguePDUMapProviderAbort creates a MAPDialoguePDU with the map-providerAbort alternative.
func NewMAPDialoguePDUMapProviderAbort(v MAPProviderAbortInfo) MAPDialoguePDU {
	return MAPDialoguePDU{
		Choice:           MAPDialoguePDUChoiceMapProviderAbort,
		MapProviderAbort: &v,
	}
}

// MAPOpenInfo represents the ASN.1 type MAP-OpenInfo (SEQUENCE).
type MAPOpenInfo struct {
	DestinationReference *AddressString      `asn1:"tag:0,context,implicit,optional" json:"DestinationReference,omitempty"`
	OriginationReference *AddressString      `asn1:"tag:1,context,implicit,optional" json:"OriginationReference,omitempty"`
	ExtensionContainer   *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_            int64               `asn1:"-" json:"-"`
	ExtPresent_          []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MAPAcceptInfo represents the ASN.1 type MAP-AcceptInfo (SEQUENCE).
type MAPAcceptInfo struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MAPCloseInfo represents the ASN.1 type MAP-CloseInfo (SEQUENCE).
type MAPCloseInfo struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MAPRefuseInfo represents the ASN.1 type MAP-RefuseInfo (SEQUENCE).
type MAPRefuseInfo struct {
	Reason                        Reason                    `asn1:""`
	ExtensionContainer            *ExtensionContainer       `asn1:",optional" json:"ExtensionContainer,omitempty"`
	AlternativeApplicationContext *runtime.ObjectIdentifier `asn1:",optional" json:"AlternativeApplicationContext,omitempty"`
	ExtCount_                     int64                     `asn1:"-" json:"-"`
	ExtPresent_                   []bool                    `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// Reason represents the ASN.1 ENUMERATED type Reason.
type Reason int64

const (
	ReasonNoReasonGiven               Reason = 0
	ReasonInvalidDestinationReference Reason = 1
	ReasonInvalidOriginatingReference Reason = 2
)

func (v Reason) String() string {
	switch v {
	case ReasonNoReasonGiven:
		return "noReasonGiven"
	case ReasonInvalidDestinationReference:
		return "invalidDestinationReference"
	case ReasonInvalidOriginatingReference:
		return "invalidOriginatingReference"
	default:
		return "unknown"
	}
}

// MAPUserAbortInfo represents the ASN.1 type MAP-UserAbortInfo (SEQUENCE).
type MAPUserAbortInfo struct {
	MapUserAbortChoice MAPUserAbortChoice  `asn1:""`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MAPUserAbortChoice choice constants.
const (
	MAPUserAbortChoiceChoiceUserSpecificReason               = 1
	MAPUserAbortChoiceChoiceUserResourceLimitation           = 2
	MAPUserAbortChoiceChoiceResourceUnavailable              = 3
	MAPUserAbortChoiceChoiceApplicationProcedureCancellation = 4
)

// MAPUserAbortChoice represents the ASN.1 CHOICE type MAP-UserAbortChoice.
type MAPUserAbortChoice struct {
	Choice                           int
	berReplayNode_                   *ber.ReplayNode              `json:"-"`
	UserSpecificReason               *struct{}                    `json:"UserSpecificReason,omitempty"`
	UserResourceLimitation           *struct{}                    `json:"UserResourceLimitation,omitempty"`
	ResourceUnavailable              *ResourceUnavailableReason   `json:"ResourceUnavailable,omitempty"`
	ApplicationProcedureCancellation *ProcedureCancellationReason `json:"ApplicationProcedureCancellation,omitempty"`
}

// NewMAPUserAbortChoiceUserSpecificReason creates a MAPUserAbortChoice with the userSpecificReason alternative.
func NewMAPUserAbortChoiceUserSpecificReason(v struct{}) MAPUserAbortChoice {
	return MAPUserAbortChoice{
		Choice:             MAPUserAbortChoiceChoiceUserSpecificReason,
		UserSpecificReason: &v,
	}
}

// NewMAPUserAbortChoiceUserResourceLimitation creates a MAPUserAbortChoice with the userResourceLimitation alternative.
func NewMAPUserAbortChoiceUserResourceLimitation(v struct{}) MAPUserAbortChoice {
	return MAPUserAbortChoice{
		Choice:                 MAPUserAbortChoiceChoiceUserResourceLimitation,
		UserResourceLimitation: &v,
	}
}

// NewMAPUserAbortChoiceResourceUnavailable creates a MAPUserAbortChoice with the resourceUnavailable alternative.
func NewMAPUserAbortChoiceResourceUnavailable(v ResourceUnavailableReason) MAPUserAbortChoice {
	return MAPUserAbortChoice{
		Choice:              MAPUserAbortChoiceChoiceResourceUnavailable,
		ResourceUnavailable: &v,
	}
}

// NewMAPUserAbortChoiceApplicationProcedureCancellation creates a MAPUserAbortChoice with the applicationProcedureCancellation alternative.
func NewMAPUserAbortChoiceApplicationProcedureCancellation(v ProcedureCancellationReason) MAPUserAbortChoice {
	return MAPUserAbortChoice{
		Choice:                           MAPUserAbortChoiceChoiceApplicationProcedureCancellation,
		ApplicationProcedureCancellation: &v,
	}
}

// ResourceUnavailableReason represents the ASN.1 ENUMERATED type ResourceUnavailableReason.
type ResourceUnavailableReason int64

const (
	ResourceUnavailableReasonShortTermResourceLimitation ResourceUnavailableReason = 0
	ResourceUnavailableReasonLongTermResourceLimitation  ResourceUnavailableReason = 1
)

func (v ResourceUnavailableReason) String() string {
	switch v {
	case ResourceUnavailableReasonShortTermResourceLimitation:
		return "shortTermResourceLimitation"
	case ResourceUnavailableReasonLongTermResourceLimitation:
		return "longTermResourceLimitation"
	default:
		return "unknown"
	}
}

// ProcedureCancellationReason represents the ASN.1 ENUMERATED type ProcedureCancellationReason.
type ProcedureCancellationReason int64

const (
	ProcedureCancellationReasonHandoverCancellation       ProcedureCancellationReason = 0
	ProcedureCancellationReasonRadioChannelRelease        ProcedureCancellationReason = 1
	ProcedureCancellationReasonNetworkPathRelease         ProcedureCancellationReason = 2
	ProcedureCancellationReasonCallRelease                ProcedureCancellationReason = 3
	ProcedureCancellationReasonAssociatedProcedureFailure ProcedureCancellationReason = 4
	ProcedureCancellationReasonTandemDialogueRelease      ProcedureCancellationReason = 5
	ProcedureCancellationReasonRemoteOperationsFailure    ProcedureCancellationReason = 6
)

func (v ProcedureCancellationReason) String() string {
	switch v {
	case ProcedureCancellationReasonHandoverCancellation:
		return "handoverCancellation"
	case ProcedureCancellationReasonRadioChannelRelease:
		return "radioChannelRelease"
	case ProcedureCancellationReasonNetworkPathRelease:
		return "networkPathRelease"
	case ProcedureCancellationReasonCallRelease:
		return "callRelease"
	case ProcedureCancellationReasonAssociatedProcedureFailure:
		return "associatedProcedureFailure"
	case ProcedureCancellationReasonTandemDialogueRelease:
		return "tandemDialogueRelease"
	case ProcedureCancellationReasonRemoteOperationsFailure:
		return "remoteOperationsFailure"
	default:
		return "unknown"
	}
}

// MAPProviderAbortInfo represents the ASN.1 type MAP-ProviderAbortInfo (SEQUENCE).
type MAPProviderAbortInfo struct {
	MapProviderAbortReason MAPProviderAbortReason `asn1:""`
	ExtensionContainer     *ExtensionContainer    `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_              int64                  `asn1:"-" json:"-"`
	ExtPresent_            []bool                 `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MAPProviderAbortReason represents the ASN.1 ENUMERATED type MAP-ProviderAbortReason.
type MAPProviderAbortReason int64

const (
	MAPProviderAbortReasonAbnormalDialogue MAPProviderAbortReason = 0
	MAPProviderAbortReasonInvalidPDU       MAPProviderAbortReason = 1
)

func (v MAPProviderAbortReason) String() string {
	switch v {
	case MAPProviderAbortReasonAbnormalDialogue:
		return "abnormalDialogue"
	case MAPProviderAbortReasonInvalidPDU:
		return "invalidPDU"
	default:
		return "unknown"
	}
}

// MarshalBER encodes MAPDialoguePDU to BER format.
func (v *MAPDialoguePDU) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MAPDialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MAPDialoguePDU).MarshalBER, (*MAPDialoguePDU).marshalBER, 3)

}
func (v *MAPDialoguePDU) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *MAPDialoguePDU) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case MAPDialoguePDUChoiceMapOpen:
		if v.MapOpen == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-open is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.MapOpen.MarshalBER(ber.ChildEncodeOptions(opts, "map-open")...)
		if err != nil {
			return nil, qualifyBERError(err, "map-open", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "map-open", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case MAPDialoguePDUChoiceMapAccept:
		if v.MapAccept == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-accept is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.MapAccept.MarshalBER(ber.ChildEncodeOptions(opts, "map-accept")...)
		if err != nil {
			return nil, qualifyBERError(err, "map-accept", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "map-accept", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case MAPDialoguePDUChoiceMapClose:
		if v.MapClose == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-close is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.MapClose.MarshalBER(ber.ChildEncodeOptions(opts, "map-close")...)
		if err != nil {
			return nil, qualifyBERError(err, "map-close", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "map-close", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case MAPDialoguePDUChoiceMapRefuse:
		if v.MapRefuse == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-refuse is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.MapRefuse.MarshalBER(ber.ChildEncodeOptions(opts, "map-refuse")...)
		if err != nil {
			return nil, qualifyBERError(err, "map-refuse", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "map-refuse", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	case MAPDialoguePDUChoiceMapUserAbort:
		if v.MapUserAbort == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-userAbort is nil", ber.ErrInvalidValue)
		}
		enc_4, err := v.MapUserAbort.MarshalBER(ber.ChildEncodeOptions(opts, "map-userAbort")...)
		if err != nil {
			return nil, qualifyBERError(err, "map-userAbort", "encoding", false)
		}
		retagged_enc_4, tagErr_enc_4 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_4)
		if tagErr_enc_4 != nil {
			return nil, qualifyBERError(tagErr_enc_4, "map-userAbort", "encoding", false)
		}
		enc_4 = retagged_enc_4
		return enc_4, nil
	case MAPDialoguePDUChoiceMapProviderAbort:
		if v.MapProviderAbort == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-providerAbort is nil", ber.ErrInvalidValue)
		}
		enc_5, err := v.MapProviderAbort.MarshalBER(ber.ChildEncodeOptions(opts, "map-providerAbort")...)
		if err != nil {
			return nil, qualifyBERError(err, "map-providerAbort", "encoding", false)
		}
		retagged_enc_5, tagErr_enc_5 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_5)
		if tagErr_enc_5 != nil {
			return nil, qualifyBERError(tagErr_enc_5, "map-providerAbort", "encoding", false)
		}
		enc_5 = retagged_enc_5
		return enc_5, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for MAPDialoguePDU", v.Choice)
	}
}

// MarshalDER encodes MAPDialoguePDU to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MAPDialoguePDU) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MAPDialoguePDU receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case MAPDialoguePDUChoiceMapOpen:
		if v.MapOpen == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-open is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.MapOpen.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "map-open", "encoding", true)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "map-open", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "map-open", "encoding", true)
		}
		return enc_der_0, nil
	case MAPDialoguePDUChoiceMapAccept:
		if v.MapAccept == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-accept is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.MapAccept.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "map-accept", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "map-accept", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "map-accept", "encoding", true)
		}
		return enc_der_1, nil
	case MAPDialoguePDUChoiceMapClose:
		if v.MapClose == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-close is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.MapClose.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "map-close", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "map-close", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "map-close", "encoding", true)
		}
		return enc_der_2, nil
	case MAPDialoguePDUChoiceMapRefuse:
		if v.MapRefuse == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-refuse is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.MapRefuse.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "map-refuse", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "map-refuse", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "map-refuse", "encoding", true)
		}
		return enc_der_3, nil
	case MAPDialoguePDUChoiceMapUserAbort:
		if v.MapUserAbort == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-userAbort is nil", ber.ErrInvalidValue)
		}
		enc_der_4, err := v.MapUserAbort.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "map-userAbort", "encoding", true)
		}
		retagged_enc_der_4, tagErr_enc_der_4 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_4)
		if tagErr_enc_der_4 != nil {
			return nil, qualifyBERError(tagErr_enc_der_4, "map-userAbort", "encoding", true)
		}
		enc_der_4 = retagged_enc_der_4
		if derErr := ber.ValidateDEREncodedElement(enc_der_4); derErr != nil {
			return nil, qualifyBERError(derErr, "map-userAbort", "encoding", true)
		}
		return enc_der_4, nil
	case MAPDialoguePDUChoiceMapProviderAbort:
		if v.MapProviderAbort == nil {
			return nil, fmt.Errorf("%w: choice MAPDialoguePDU: map-providerAbort is nil", ber.ErrInvalidValue)
		}
		enc_der_5, err := v.MapProviderAbort.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "map-providerAbort", "encoding", true)
		}
		retagged_enc_der_5, tagErr_enc_der_5 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_der_5)
		if tagErr_enc_der_5 != nil {
			return nil, qualifyBERError(tagErr_enc_der_5, "map-providerAbort", "encoding", true)
		}
		enc_der_5 = retagged_enc_der_5
		if derErr := ber.ValidateDEREncodedElement(enc_der_5); derErr != nil {
			return nil, qualifyBERError(derErr, "map-providerAbort", "encoding", true)
		}
		return enc_der_5, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case MAPDialoguePDUChoiceMapOpen:
			return nil, qualifyBERError(err, "map-open", "encoding", true)
		case MAPDialoguePDUChoiceMapAccept:
			return nil, qualifyBERError(err, "map-accept", "encoding", true)
		case MAPDialoguePDUChoiceMapClose:
			return nil, qualifyBERError(err, "map-close", "encoding", true)
		case MAPDialoguePDUChoiceMapRefuse:
			return nil, qualifyBERError(err, "map-refuse", "encoding", true)
		case MAPDialoguePDUChoiceMapUserAbort:
			return nil, qualifyBERError(err, "map-userAbort", "encoding", true)
		case MAPDialoguePDUChoiceMapProviderAbort:
			return nil, qualifyBERError(err, "map-providerAbort", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding MAPDialoguePDU as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *MAPDialoguePDU) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MAPDialoguePDU from BER/DER format.
func (destination *MAPDialoguePDU) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MAPDialoguePDU destination is nil", ber.ErrInvalidValue)
	}
	v := new(MAPDialoguePDU)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "MAP-DialogueInformation.MAP-DialoguePDU", "child", (*MAPDialoguePDU).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MAPDialoguePDU).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MAPDialoguePDU{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for MAPDialoguePDU CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for MAPDialoguePDU: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding MAPDialoguePDU CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPDialoguePDU", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "MAPDialoguePDU.map-open", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "MAPDialoguePDU.map-accept", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "MAPDialoguePDU.map-close", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "MAPDialoguePDU.map-refuse", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "MAPDialoguePDU.map-userAbort", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "MAPDialoguePDU.map-providerAbort", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = MAPDialoguePDUChoiceMapOpen
		ber.MarkPreflightTarget(opts, "map-open", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "map-open", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec MAPOpenInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "map-open")...); unmErr != nil {
			return qualifyBERError(unmErr, "map-open", "decoding", false)
		}
		v.MapOpen = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = MAPDialoguePDUChoiceMapAccept
		ber.MarkPreflightTarget(opts, "map-accept", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "map-accept", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec MAPAcceptInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "map-accept")...); unmErr != nil {
			return qualifyBERError(unmErr, "map-accept", "decoding", false)
		}
		v.MapAccept = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = MAPDialoguePDUChoiceMapClose
		ber.MarkPreflightTarget(opts, "map-close", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "map-close", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec MAPCloseInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "map-close")...); unmErr != nil {
			return qualifyBERError(unmErr, "map-close", "decoding", false)
		}
		v.MapClose = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = MAPDialoguePDUChoiceMapRefuse
		ber.MarkPreflightTarget(opts, "map-refuse", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "map-refuse", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec MAPRefuseInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "map-refuse")...); unmErr != nil {
			return qualifyBERError(unmErr, "map-refuse", "decoding", false)
		}
		v.MapRefuse = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = MAPDialoguePDUChoiceMapUserAbort
		ber.MarkPreflightTarget(opts, "map-userAbort", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "map-userAbort", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec MAPUserAbortInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "map-userAbort")...); unmErr != nil {
			return qualifyBERError(unmErr, "map-userAbort", "decoding", false)
		}
		v.MapUserAbort = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == true {
		v.Choice = MAPDialoguePDUChoiceMapProviderAbort
		ber.MarkPreflightTarget(opts, "map-providerAbort", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "map-providerAbort", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec MAPProviderAbortInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "map-providerAbort")...); unmErr != nil {
			return qualifyBERError(unmErr, "map-providerAbort", "decoding", false)
		}
		v.MapProviderAbort = &dec
	} else {
		return fmt.Errorf("unknown tag %s for MAPDialoguePDU CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes MAPOpenInfo to BER format.
func (v *MAPOpenInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MAPOpenInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MAPOpenInfo).MarshalBER, (*MAPOpenInfo).marshalBER, 3)

}
func (v *MAPOpenInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.DestinationReference != nil {
		if len(*v.DestinationReference) < 1 || len(*v.DestinationReference) > 20 {
			if constraintErr := checkEncodedLength(opts, sc55658_0, "51.5", "destinationReference", "SIZE (1..20)", len(*v.DestinationReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_destinationreference, encodeErr_enc_destinationreference := ber.EncodeOctetString([]byte(*v.DestinationReference))
		if encodeErr_enc_destinationreference != nil {
			return nil, qualifyBERError(encodeErr_enc_destinationreference, "destinationReference", "encoding", false)
		}
		retagged_enc_destinationreference, tagErr_enc_destinationreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_destinationreference)
		if tagErr_enc_destinationreference != nil {
			return nil, qualifyBERError(tagErr_enc_destinationreference, "destinationReference", "encoding", false)
		}
		enc_destinationreference = retagged_enc_destinationreference
		children = append(children, enc_destinationreference...)
	}
	if v.OriginationReference != nil {
		if len(*v.OriginationReference) < 1 || len(*v.OriginationReference) > 20 {
			if constraintErr := checkEncodedLength(opts, sc55658_0, "51.5", "originationReference", "SIZE (1..20)", len(*v.OriginationReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_originationreference, encodeErr_enc_originationreference := ber.EncodeOctetString([]byte(*v.OriginationReference))
		if encodeErr_enc_originationreference != nil {
			return nil, qualifyBERError(encodeErr_enc_originationreference, "originationReference", "encoding", false)
		}
		retagged_enc_originationreference, tagErr_enc_originationreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_originationreference)
		if tagErr_enc_originationreference != nil {
			return nil, qualifyBERError(tagErr_enc_originationreference, "originationReference", "encoding", false)
		}
		enc_originationreference = retagged_enc_originationreference
		children = append(children, enc_originationreference...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sc55658_0, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sc55658_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MAPOpenInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MAPOpenInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MAPOpenInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MAPOpenInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.DestinationReference != nil {
		if len(*v.DestinationReference) < 1 || len(*v.DestinationReference) > 20 {
			if constraintErr := checkEncodedLength(nil, sc55658_0, "51.5", "destinationReference", "SIZE (1..20)", len(*v.DestinationReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_destinationreference, encodeErr_enc_destinationreference := ber.EncodeOctetString([]byte(*v.DestinationReference))
		if encodeErr_enc_destinationreference != nil {
			return nil, qualifyBERError(encodeErr_enc_destinationreference, "destinationReference", "encoding", true)
		}
		retagged_enc_destinationreference, tagErr_enc_destinationreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_destinationreference)
		if tagErr_enc_destinationreference != nil {
			return nil, qualifyBERError(tagErr_enc_destinationreference, "destinationReference", "encoding", true)
		}
		enc_destinationreference = retagged_enc_destinationreference
		children = append(children, enc_destinationreference...)
	}
	if v.OriginationReference != nil {
		if len(*v.OriginationReference) < 1 || len(*v.OriginationReference) > 20 {
			if constraintErr := checkEncodedLength(nil, sc55658_0, "51.5", "originationReference", "SIZE (1..20)", len(*v.OriginationReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_originationreference, encodeErr_enc_originationreference := ber.EncodeOctetString([]byte(*v.OriginationReference))
		if encodeErr_enc_originationreference != nil {
			return nil, qualifyBERError(encodeErr_enc_originationreference, "originationReference", "encoding", true)
		}
		retagged_enc_originationreference, tagErr_enc_originationreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_originationreference)
		if tagErr_enc_originationreference != nil {
			return nil, qualifyBERError(tagErr_enc_originationreference, "originationReference", "encoding", true)
		}
		enc_originationreference = retagged_enc_originationreference
		children = append(children, enc_originationreference...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sc55658_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sc55658_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MAPOpenInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MAPOpenInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MAPOpenInfo from BER/DER format.
func (destination *MAPOpenInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MAPOpenInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(MAPOpenInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sc55658_0, "child", (*MAPOpenInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MAPOpenInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MAPOpenInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MAPOpenInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPOpenInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode destinationReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "destinationReference", content[offset:])
				decodedTag_destinationreference, n_destinationreference, rawVal_destinationreference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "destinationReference", "decoding", false)
				}
				if decodedTag_destinationreference.Class != tag.ClassContextSpecific || decodedTag_destinationreference.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_destinationreference), "destinationReference", "decoding", false)
				}
				decVal_destinationreference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_destinationreference.Constructed, rawVal_destinationreference, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "destinationReference", "decoding", false)
				}
				tmp_destinationreference := AddressString(decVal_destinationreference)
				v.DestinationReference = &tmp_destinationreference
				if offset > len(content) || n_destinationreference < 0 || n_destinationreference >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_destinationreference
				if len(*v.DestinationReference) < 1 || len(*v.DestinationReference) > 20 {
					if constraintErr := checkDecodedLength(opts, sc55658_0, "51.5", "destinationReference", "SIZE (1..20)", len(*v.DestinationReference)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode originationReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "originationReference", content[offset:])
				decodedTag_originationreference, n_originationreference, rawVal_originationreference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "originationReference", "decoding", false)
				}
				if decodedTag_originationreference.Class != tag.ClassContextSpecific || decodedTag_originationreference.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_originationreference), "originationReference", "decoding", false)
				}
				decVal_originationreference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_originationreference.Constructed, rawVal_originationreference, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "originationReference", "decoding", false)
				}
				tmp_originationreference := AddressString(decVal_originationreference)
				v.OriginationReference = &tmp_originationreference
				if offset < 0 || offset >
					len(content) || n_originationreference < 0 || n_originationreference >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_originationreference
				if len(*v.OriginationReference) < 1 || len(*v.OriginationReference) > 20 {
					if constraintErr := checkDecodedLength(opts, sc55658_0, "51.5", "originationReference", "SIZE (1..20)", len(*v.OriginationReference)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MAPOpenInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MAPOpenInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sc55658_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes MAPAcceptInfo to BER format.
func (v *MAPAcceptInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MAPAcceptInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MAPAcceptInfo).MarshalBER, (*MAPAcceptInfo).marshalBER, 3)

}
func (v *MAPAcceptInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sc55658_1, children, i, &base_); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sc55658_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MAPAcceptInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MAPAcceptInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MAPAcceptInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MAPAcceptInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sc55658_1, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sc55658_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MAPAcceptInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MAPAcceptInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MAPAcceptInfo from BER/DER format.
func (destination *MAPAcceptInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MAPAcceptInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(MAPAcceptInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sc55658_1, "child", (*MAPAcceptInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MAPAcceptInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MAPAcceptInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MAPAcceptInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPAcceptInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MAPAcceptInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MAPAcceptInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sc55658_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes MAPCloseInfo to BER format.
func (v *MAPCloseInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MAPCloseInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MAPCloseInfo).MarshalBER, (*MAPCloseInfo).marshalBER, 3)

}
func (v *MAPCloseInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sc55658_2, children, i, &base_); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sc55658_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MAPCloseInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MAPCloseInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MAPCloseInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MAPCloseInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sc55658_2, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sc55658_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MAPCloseInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MAPCloseInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MAPCloseInfo from BER/DER format.
func (destination *MAPCloseInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MAPCloseInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(MAPCloseInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sc55658_2, "child", (*MAPCloseInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MAPCloseInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MAPCloseInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MAPCloseInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPCloseInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MAPCloseInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MAPCloseInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sc55658_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes MAPRefuseInfo to BER format.
func (v *MAPRefuseInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MAPRefuseInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MAPRefuseInfo).MarshalBER, (*MAPRefuseInfo).marshalBER, 3)

}
func (v *MAPRefuseInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.Reason) != 0 && int64(v.Reason) != 1 && int64(v.Reason) != 2 {
		if constraintErr := checkEncodedValue(opts, sc55658_3, "20", "reason", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(v.Reason))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reason := ber.EncodeEnumerated(int64(v.Reason))
	children = append(children, enc_reason...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlternativeApplicationContext != nil {
		enc_alternativeapplicationcontext, oidErr := ber.EncodeObjectIdentifierChecked(*v.AlternativeApplicationContext)
		if oidErr != nil {
			return nil, qualifyBERError(oidErr, "alternativeApplicationContext", "encoding", false)
		}
		children = append(children, enc_alternativeapplicationcontext...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sc55658_3, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 6) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sc55658_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MAPRefuseInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MAPRefuseInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MAPRefuseInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MAPRefuseInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.Reason) != 0 && int64(v.Reason) != 1 && int64(v.Reason) != 2 {
		if constraintErr := checkEncodedValue(nil, sc55658_3, "20", "reason", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(v.Reason))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_reason := ber.EncodeEnumerated(int64(v.Reason))
	children = append(children, enc_reason...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.AlternativeApplicationContext != nil {
		enc_alternativeapplicationcontext, oidErr := ber.EncodeObjectIdentifierChecked(*v.AlternativeApplicationContext)
		if oidErr != nil {
			return nil, qualifyBERError(oidErr, "alternativeApplicationContext", "encoding", true)
		}
		children = append(children, enc_alternativeapplicationcontext...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sc55658_3, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 6) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sc55658_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MAPRefuseInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MAPRefuseInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MAPRefuseInfo from BER/DER format.
func (destination *MAPRefuseInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MAPRefuseInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(MAPRefuseInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sc55658_3, "child", (*MAPRefuseInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MAPRefuseInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MAPRefuseInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MAPRefuseInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPRefuseInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode reason
	if offset >= len(content) {
		return fmt.Errorf("missing required field reason")
	}
	{
		ber.MarkPreflightTarget(opts, "reason", content[offset:])
		val_reason, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "reason", "decoding", false)
		}
		v.Reason = Reason(val_reason)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.Reason) != 0 && int64(v.Reason) != 1 && int64(v.Reason) != 2 {
			if constraintErr := checkDecodedValue(opts, sc55658_3, "20", "reason", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(v.Reason))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode alternativeApplicationContext
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "alternativeApplicationContext", content[offset:])
				val_alternativeapplicationcontext, n, err := ber.DecodeObjectIdentifier(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "alternativeApplicationContext", "decoding", false)
				}
				tmp_alternativeapplicationcontext := val_alternativeapplicationcontext
				v.AlternativeApplicationContext = &tmp_alternativeapplicationcontext
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MAPRefuseInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 6) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MAPRefuseInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sc55658_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes MAPUserAbortInfo to BER format.
func (v *MAPUserAbortInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MAPUserAbortInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MAPUserAbortInfo).MarshalBER, (*MAPUserAbortInfo).marshalBER, 3)

}
func (v *MAPUserAbortInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_mapuserabortchoice, err := v.MapUserAbortChoice.MarshalBER(ber.ChildEncodeOptions(opts, "map-UserAbortChoice")...)
	if err != nil {
		return nil, qualifyBERError(err, "map-UserAbortChoice", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_mapuserabortchoice)
	children = append(children, enc_mapuserabortchoice...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sc55658_4, children, i, &base_); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sc55658_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MAPUserAbortInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MAPUserAbortInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MAPUserAbortInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MAPUserAbortInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_mapuserabortchoice, err := v.MapUserAbortChoice.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "map-UserAbortChoice", "encoding", true)
	}
	children = append(children, enc_mapuserabortchoice...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sc55658_4, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sc55658_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MAPUserAbortInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MAPUserAbortInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MAPUserAbortInfo from BER/DER format.
func (destination *MAPUserAbortInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MAPUserAbortInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(MAPUserAbortInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sc55658_4, "child", (*MAPUserAbortInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MAPUserAbortInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MAPUserAbortInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MAPUserAbortInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPUserAbortInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode map-UserAbortChoice
	if offset >= len(content) {
		return fmt.Errorf("missing required field map-UserAbortChoice")
	}
	{
		ber.MarkPreflightTarget(opts, "map-UserAbortChoice", content[offset:])
		// Decode nested CHOICE (MAPUserAbortChoice)
		_, n_mapuserabortchoice, _, tlvErr_mapuserabortchoice := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_mapuserabortchoice != nil {
			return qualifyBERError(tlvErr_mapuserabortchoice, "map-UserAbortChoice", "decoding", false)
		}
		if offset > len(content) || n_mapuserabortchoice < 0 || n_mapuserabortchoice > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.MapUserAbortChoice.UnmarshalBER(content[offset:offset+n_mapuserabortchoice], ber.ChildDecodeOptions(opts, "map-UserAbortChoice")...); unmErr != nil {
			return qualifyBERError(unmErr, "map-UserAbortChoice", "decoding", false)
		}
		if offset > len(content) || n_mapuserabortchoice < 0 || n_mapuserabortchoice > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_mapuserabortchoice
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MAPUserAbortInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MAPUserAbortInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sc55658_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes MAPUserAbortChoice to BER format.
func (v *MAPUserAbortChoice) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MAPUserAbortChoice receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MAPUserAbortChoice).MarshalBER, (*MAPUserAbortChoice).marshalBER, 3)

}
func (v *MAPUserAbortChoice) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *MAPUserAbortChoice) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case MAPUserAbortChoiceChoiceUserSpecificReason:
		enc_0 := ber.EncodeNull()
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "userSpecificReason", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case MAPUserAbortChoiceChoiceUserResourceLimitation:
		enc_1 := ber.EncodeNull()
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "userResourceLimitation", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case MAPUserAbortChoiceChoiceResourceUnavailable:
		if v.ResourceUnavailable == nil {
			return nil, fmt.Errorf("%w: choice MAPUserAbortChoice: resourceUnavailable is nil", ber.ErrInvalidValue)
		}
		enc_2 := ber.EncodeEnumerated(int64(*v.ResourceUnavailable))
		if int64(*v.ResourceUnavailable) != 0 && int64(*v.ResourceUnavailable) != 1 {
			if constraintErr := checkEncodedValue(opts, sc55658_5, "20", "resourceUnavailable", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.ResourceUnavailable))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "resourceUnavailable", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case MAPUserAbortChoiceChoiceApplicationProcedureCancellation:
		if v.ApplicationProcedureCancellation == nil {
			return nil, fmt.Errorf("%w: choice MAPUserAbortChoice: applicationProcedureCancellation is nil", ber.ErrInvalidValue)
		}
		enc_3 := ber.EncodeEnumerated(int64(*v.ApplicationProcedureCancellation))
		if int64(*v.ApplicationProcedureCancellation) != 0 && int64(*v.ApplicationProcedureCancellation) != 1 && int64(*v.ApplicationProcedureCancellation) != 2 && int64(*v.ApplicationProcedureCancellation) != 3 && int64(*v.ApplicationProcedureCancellation) != 4 && int64(*v.ApplicationProcedureCancellation) != 5 && int64(*v.ApplicationProcedureCancellation) != 6 {
			if constraintErr := checkEncodedValue(opts, sc55658_5, "20", "applicationProcedureCancellation", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", ber.ObserveInteger(int64(*v.ApplicationProcedureCancellation))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "applicationProcedureCancellation", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for MAPUserAbortChoice", v.Choice)
	}
}

// MarshalDER encodes MAPUserAbortChoice to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MAPUserAbortChoice) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MAPUserAbortChoice receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case MAPUserAbortChoiceChoiceUserSpecificReason:
			return nil, qualifyBERError(err, "userSpecificReason", "encoding", true)
		case MAPUserAbortChoiceChoiceUserResourceLimitation:
			return nil, qualifyBERError(err, "userResourceLimitation", "encoding", true)
		case MAPUserAbortChoiceChoiceResourceUnavailable:
			return nil, qualifyBERError(err, "resourceUnavailable", "encoding", true)
		case MAPUserAbortChoiceChoiceApplicationProcedureCancellation:
			return nil, qualifyBERError(err, "applicationProcedureCancellation", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding MAPUserAbortChoice as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *MAPUserAbortChoice) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MAPUserAbortChoice from BER/DER format.
func (destination *MAPUserAbortChoice) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MAPUserAbortChoice destination is nil", ber.ErrInvalidValue)
	}
	v := new(MAPUserAbortChoice)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sc55658_5, "child", (*MAPUserAbortChoice).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MAPUserAbortChoice).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MAPUserAbortChoice{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for MAPUserAbortChoice CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for MAPUserAbortChoice: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding MAPUserAbortChoice CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPUserAbortChoice", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "MAPUserAbortChoice.userSpecificReason", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "MAPUserAbortChoice.userResourceLimitation", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "MAPUserAbortChoice.resourceUnavailable", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "MAPUserAbortChoice.applicationProcedureCancellation", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == false {
		v.Choice = MAPUserAbortChoiceChoiceUserSpecificReason
		ber.MarkPreflightTarget(opts, "userSpecificReason", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "userSpecificReason", "decoding", false)
		}
		_ = rawVal
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "userSpecificReason", "decoding", false)
		}
		v.UserSpecificReason = &struct{}{}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = MAPUserAbortChoiceChoiceUserResourceLimitation
		ber.MarkPreflightTarget(opts, "userResourceLimitation", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "userResourceLimitation", "decoding", false)
		}
		_ = rawVal
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "userResourceLimitation", "decoding", false)
		}
		v.UserResourceLimitation = &struct{}{}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = MAPUserAbortChoiceChoiceResourceUnavailable
		ber.MarkPreflightTarget(opts, "resourceUnavailable", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "resourceUnavailable", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeEnumeratedValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "resourceUnavailable", "decoding", false)
		}
		tmp := ResourceUnavailableReason(decVal)
		v.ResourceUnavailable = &tmp
		if int64(*v.ResourceUnavailable) != 0 && int64(*v.ResourceUnavailable) != 1 {
			if constraintErr := checkDecodedValue(opts, sc55658_5, "20", "resourceUnavailable", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.ResourceUnavailable))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == false {
		v.Choice = MAPUserAbortChoiceChoiceApplicationProcedureCancellation
		ber.MarkPreflightTarget(opts, "applicationProcedureCancellation", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "applicationProcedureCancellation", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeEnumeratedValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "applicationProcedureCancellation", "decoding", false)
		}
		tmp := ProcedureCancellationReason(decVal)
		v.ApplicationProcedureCancellation = &tmp
		if int64(*v.ApplicationProcedureCancellation) != 0 && int64(*v.ApplicationProcedureCancellation) != 1 && int64(*v.ApplicationProcedureCancellation) != 2 && int64(*v.ApplicationProcedureCancellation) != 3 && int64(*v.ApplicationProcedureCancellation) != 4 && int64(*v.ApplicationProcedureCancellation) != 5 && int64(*v.ApplicationProcedureCancellation) != 6 {
			if constraintErr := checkDecodedValue(opts, sc55658_5, "20", "applicationProcedureCancellation", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", ber.ObserveInteger(int64(*v.ApplicationProcedureCancellation))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for MAPUserAbortChoice CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes MAPProviderAbortInfo to BER format.
func (v *MAPProviderAbortInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: MAPProviderAbortInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*MAPProviderAbortInfo).MarshalBER, (*MAPProviderAbortInfo).marshalBER, 3)

}
func (v *MAPProviderAbortInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.MapProviderAbortReason) != 0 && int64(v.MapProviderAbortReason) != 1 {
		if constraintErr := checkEncodedValue(opts, sc55658_6, "20", "map-ProviderAbortReason", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.MapProviderAbortReason))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mapproviderabortreason := ber.EncodeEnumerated(int64(v.MapProviderAbortReason))
	children = append(children, enc_mapproviderabortreason...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sc55658_6, children, i, &base_); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sc55658_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *MAPProviderAbortInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes MAPProviderAbortInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *MAPProviderAbortInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: MAPProviderAbortInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.MapProviderAbortReason) != 0 && int64(v.MapProviderAbortReason) != 1 {
		if constraintErr := checkEncodedValue(nil, sc55658_6, "20", "map-ProviderAbortReason", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.MapProviderAbortReason))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mapproviderabortreason := ber.EncodeEnumerated(int64(v.MapProviderAbortReason))
	children = append(children, enc_mapproviderabortreason...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sc55658_6, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sc55658_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding MAPProviderAbortInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *MAPProviderAbortInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes MAPProviderAbortInfo from BER/DER format.
func (destination *MAPProviderAbortInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: MAPProviderAbortInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(MAPProviderAbortInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sc55658_6, "child", (*MAPProviderAbortInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = MAPProviderAbortInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*MAPProviderAbortInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding MAPProviderAbortInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "MAPProviderAbortInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode map-ProviderAbortReason
	if offset >= len(content) {
		return fmt.Errorf("missing required field map-ProviderAbortReason")
	}
	{
		ber.MarkPreflightTarget(opts, "map-ProviderAbortReason", content[offset:])
		val_mapproviderabortreason, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "map-ProviderAbortReason", "decoding", false)
		}
		v.MapProviderAbortReason = MAPProviderAbortReason(val_mapproviderabortreason)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.MapProviderAbortReason) != 0 && int64(v.MapProviderAbortReason) != 1 {
			if constraintErr := checkDecodedValue(opts, sc55658_6, "20", "map-ProviderAbortReason", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.MapProviderAbortReason))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "MAPProviderAbortInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "MAPProviderAbortInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sc55658_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

const (
	sc55658_0 = "MAP-DialogueInformation.MAP-OpenInfo"
	sc55658_1 = "MAP-DialogueInformation.MAP-AcceptInfo"
	sc55658_2 = "MAP-DialogueInformation.MAP-CloseInfo"
	sc55658_3 = "MAP-DialogueInformation.MAP-RefuseInfo"
	sc55658_4 = "MAP-DialogueInformation.MAP-UserAbortInfo"
	sc55658_5 = "MAP-DialogueInformation.MAP-UserAbortChoice"
	sc55658_6 = "MAP-DialogueInformation.MAP-ProviderAbortInfo"
)
