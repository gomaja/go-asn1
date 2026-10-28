// Code generated from ASN.1 module "MAP-GR-DataTypes". DO NOT EDIT.

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

// PrepareGroupCallArg represents the ASN.1 type PrepareGroupCallArg (SEQUENCE).
type PrepareGroupCallArg struct {
	Teleservice            ExtTeleserviceCode  `asn1:""`
	AsciCallReference      ASCICallReference   `asn1:""`
	CodecInfo              CODECInfo           `asn1:""`
	CipheringAlgorithm     CipheringAlgorithm  `asn1:""`
	GroupKeyNumberVkId     *GroupKeyNumber     `asn1:"tag:0,context,implicit,optional" json:"GroupKeyNumberVkId,omitempty"`
	GroupKey               *Kc                 `asn1:"tag:1,context,implicit,optional" json:"GroupKey,omitempty"`
	Priority               *EMLPPPriority      `asn1:"tag:2,context,implicit,optional" json:"Priority,omitempty"`
	UplinkFree             *struct{}           `asn1:"tag:3,context,implicit,optional" json:"UplinkFree,omitempty"`
	ExtensionContainer     *ExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	Vstk                   *VSTK               `asn1:"tag:5,context,implicit,optional" json:"Vstk,omitempty"`
	VstkRand               *VSTKRAND           `asn1:"tag:6,context,implicit,optional" json:"VstkRand,omitempty"`
	TalkerChannelParameter *struct{}           `asn1:"tag:7,context,implicit,optional" json:"TalkerChannelParameter,omitempty"`
	UplinkReplyIndicator   *struct{}           `asn1:"tag:8,context,implicit,optional" json:"UplinkReplyIndicator,omitempty"`
	ExtCount_              int64               `asn1:"-" json:"-"`
	ExtPresent_            []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// VSTK represents the ASN.1 type VSTK (OCTET_STRING).
type VSTK = []byte

// VSTKRAND represents the ASN.1 type VSTK-RAND (OCTET_STRING).
type VSTKRAND = []byte

// PrepareGroupCallRes represents the ASN.1 type PrepareGroupCallRes (SEQUENCE).
type PrepareGroupCallRes struct {
	GroupCallNumber    ISDNAddressString   `asn1:""`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SendGroupCallEndSignalArg represents the ASN.1 type SendGroupCallEndSignalArg (SEQUENCE).
type SendGroupCallEndSignalArg struct {
	Imsi               *IMSI               `asn1:",optional" json:"Imsi,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	TalkerPriority     *TalkerPriority     `asn1:"tag:0,context,implicit,optional" json:"TalkerPriority,omitempty"`
	AdditionalInfo     *AdditionalInfo     `asn1:"tag:1,context,implicit,optional" json:"AdditionalInfo,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// TalkerPriority represents the ASN.1 ENUMERATED type TalkerPriority.
type TalkerPriority int64

const (
	TalkerPriorityNormal     TalkerPriority = 0
	TalkerPriorityPrivileged TalkerPriority = 1
	TalkerPriorityEmergency  TalkerPriority = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v TalkerPriority) String() string {
	switch v {
	case TalkerPriorityNormal:
		return "normal"
	case TalkerPriorityPrivileged:
		return "privileged"
	case TalkerPriorityEmergency:
		return "emergency"
	default:
		return "unknown"
	}
}

// SendGroupCallEndSignalRes represents the ASN.1 type SendGroupCallEndSignalRes (SEQUENCE).
type SendGroupCallEndSignalRes struct {
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ForwardGroupCallSignallingArg represents the ASN.1 type ForwardGroupCallSignallingArg (SEQUENCE).
type ForwardGroupCallSignallingArg struct {
	Imsi                          *IMSI                    `asn1:",optional" json:"Imsi,omitempty"`
	UplinkRequestAck              *struct{}                `asn1:"tag:0,context,implicit,optional" json:"UplinkRequestAck,omitempty"`
	UplinkReleaseIndication       *struct{}                `asn1:"tag:1,context,implicit,optional" json:"UplinkReleaseIndication,omitempty"`
	UplinkRejectCommand           *struct{}                `asn1:"tag:2,context,implicit,optional" json:"UplinkRejectCommand,omitempty"`
	UplinkSeizedCommand           *struct{}                `asn1:"tag:3,context,implicit,optional" json:"UplinkSeizedCommand,omitempty"`
	UplinkReleaseCommand          *struct{}                `asn1:"tag:4,context,implicit,optional" json:"UplinkReleaseCommand,omitempty"`
	ExtensionContainer            *ExtensionContainer      `asn1:",optional" json:"ExtensionContainer,omitempty"`
	StateAttributes               *StateAttributes         `asn1:"tag:5,context,implicit,optional" json:"StateAttributes,omitempty"`
	TalkerPriority                *TalkerPriority          `asn1:"tag:6,context,implicit,optional" json:"TalkerPriority,omitempty"`
	AdditionalInfo                *AdditionalInfo          `asn1:"tag:7,context,implicit,optional" json:"AdditionalInfo,omitempty"`
	EmergencyModeResetCommandFlag *struct{}                `asn1:"tag:8,context,implicit,optional" json:"EmergencyModeResetCommandFlag,omitempty"`
	SmRPUI                        *SignalInfo              `asn1:"tag:9,context,implicit,optional" json:"SmRPUI,omitempty"`
	AnAPDU                        *AccessNetworkSignalInfo `asn1:"tag:10,context,implicit,optional" json:"AnAPDU,omitempty"`
	ExtCount_                     int64                    `asn1:"-" json:"-"`
	ExtPresent_                   []bool                   `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ProcessGroupCallSignallingArg represents the ASN.1 type ProcessGroupCallSignallingArg (SEQUENCE).
type ProcessGroupCallSignallingArg struct {
	UplinkRequest                 *struct{}                `asn1:"tag:0,context,implicit,optional" json:"UplinkRequest,omitempty"`
	UplinkReleaseIndication       *struct{}                `asn1:"tag:1,context,implicit,optional" json:"UplinkReleaseIndication,omitempty"`
	ReleaseGroupCall              *struct{}                `asn1:"tag:2,context,implicit,optional" json:"ReleaseGroupCall,omitempty"`
	ExtensionContainer            *ExtensionContainer      `asn1:",optional" json:"ExtensionContainer,omitempty"`
	TalkerPriority                *TalkerPriority          `asn1:"tag:3,context,implicit,optional" json:"TalkerPriority,omitempty"`
	AdditionalInfo                *AdditionalInfo          `asn1:"tag:4,context,implicit,optional" json:"AdditionalInfo,omitempty"`
	EmergencyModeResetCommandFlag *struct{}                `asn1:"tag:5,context,implicit,optional" json:"EmergencyModeResetCommandFlag,omitempty"`
	AnAPDU                        *AccessNetworkSignalInfo `asn1:"tag:6,context,implicit,optional" json:"AnAPDU,omitempty"`
	ExtCount_                     int64                    `asn1:"-" json:"-"`
	ExtPresent_                   []bool                   `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// GroupKeyNumber represents the ASN.1 type GroupKeyNumber (INTEGER).
type GroupKeyNumber = int64

// CODECInfo represents the ASN.1 type CODEC-Info (OCTET_STRING).
type CODECInfo = []byte

// CipheringAlgorithm represents the ASN.1 type CipheringAlgorithm (OCTET_STRING).
type CipheringAlgorithm = []byte

// StateAttributes represents the ASN.1 type StateAttributes (SEQUENCE).
type StateAttributes struct {
	DownlinkAttached  *struct{}       `asn1:"tag:5,context,implicit,optional" json:"DownlinkAttached,omitempty"`
	UplinkAttached    *struct{}       `asn1:"tag:6,context,implicit,optional" json:"UplinkAttached,omitempty"`
	DualCommunication *struct{}       `asn1:"tag:7,context,implicit,optional" json:"DualCommunication,omitempty"`
	CallOriginator    *struct{}       `asn1:"tag:8,context,implicit,optional" json:"CallOriginator,omitempty"`
	berReplayNode_    *ber.ReplayNode `asn1:"-" json:"-"`
}

// SendGroupCallInfoArg represents the ASN.1 type SendGroupCallInfoArg (SEQUENCE).
type SendGroupCallInfoArg struct {
	RequestedInfo      GRRequestedInfo     `asn1:""`
	GroupId            LongGroupId         `asn1:""`
	Teleservice        ExtTeleserviceCode  `asn1:""`
	CellId             *GlobalCellId       `asn1:"tag:0,context,implicit,optional" json:"CellId,omitempty"`
	Imsi               *IMSI               `asn1:"tag:1,context,implicit,optional" json:"Imsi,omitempty"`
	Tmsi               *TMSI               `asn1:"tag:2,context,implicit,optional" json:"Tmsi,omitempty"`
	AdditionalInfo     *AdditionalInfo     `asn1:"tag:3,context,implicit,optional" json:"AdditionalInfo,omitempty"`
	TalkerPriority     *TalkerPriority     `asn1:"tag:4,context,implicit,optional" json:"TalkerPriority,omitempty"`
	Cksn               *Cksn               `asn1:"tag:5,context,implicit,optional" json:"Cksn,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:"tag:6,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// GRRequestedInfo represents the ASN.1 ENUMERATED type RequestedInfo.
type GRRequestedInfo int64

const (
	GRRequestedInfoAnchorMSCAddressAndASCICallReference           GRRequestedInfo = 0
	GRRequestedInfoImsiAndAdditionalInfoAndAdditionalSubscription GRRequestedInfo = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v GRRequestedInfo) String() string {
	switch v {
	case GRRequestedInfoAnchorMSCAddressAndASCICallReference:
		return "anchorMSC-AddressAndASCI-CallReference"
	case GRRequestedInfoImsiAndAdditionalInfoAndAdditionalSubscription:
		return "imsiAndAdditionalInfoAndAdditionalSubscription"
	default:
		return "unknown"
	}
}

// SendGroupCallInfoRes represents the ASN.1 type SendGroupCallInfoRes (SEQUENCE).
type SendGroupCallInfoRes struct {
	AnchorMSCAddress        *ISDNAddressString       `asn1:"tag:0,context,implicit,optional" json:"AnchorMSCAddress,omitempty"`
	AsciCallReference       *ASCICallReference       `asn1:"tag:1,context,implicit,optional" json:"AsciCallReference,omitempty"`
	Imsi                    *IMSI                    `asn1:"tag:2,context,implicit,optional" json:"Imsi,omitempty"`
	AdditionalInfo          *AdditionalInfo          `asn1:"tag:3,context,implicit,optional" json:"AdditionalInfo,omitempty"`
	AdditionalSubscriptions *AdditionalSubscriptions `asn1:"tag:4,context,implicit,optional" json:"AdditionalSubscriptions,omitempty"`
	Kc                      *Kc                      `asn1:"tag:5,context,implicit,optional" json:"Kc,omitempty"`
	ExtensionContainer      *ExtensionContainer      `asn1:"tag:6,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes PrepareGroupCallArg to BER format.
func (v *PrepareGroupCallArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PrepareGroupCallArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PrepareGroupCallArg).MarshalBER, (*PrepareGroupCallArg).marshalBER, 3)

}
func (v *PrepareGroupCallArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
		if constraintErr := checkEncodedLength(opts, sbdb8a8_0, "51.5", "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(v.Teleservice))
	if encodeErr_enc_teleservice != nil {
		return nil, qualifyBERError(encodeErr_enc_teleservice, "teleservice", "encoding", false)
	}
	children = append(children, enc_teleservice...)
	if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
		if constraintErr := checkEncodedLength(opts, sbdb8a8_0, "51.5", "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ascicallreference, encodeErr_enc_ascicallreference := ber.EncodeOctetString([]byte(v.AsciCallReference))
	if encodeErr_enc_ascicallreference != nil {
		return nil, qualifyBERError(encodeErr_enc_ascicallreference, "asciCallReference", "encoding", false)
	}
	children = append(children, enc_ascicallreference...)
	if len(v.CodecInfo) < 5 || len(v.CodecInfo) > 10 {
		if constraintErr := checkEncodedLength(opts, sbdb8a8_0, "51.5", "codec-Info", "SIZE (5..10)", len(v.CodecInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_codecinfo, encodeErr_enc_codecinfo := ber.EncodeOctetString([]byte(v.CodecInfo))
	if encodeErr_enc_codecinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_codecinfo, "codec-Info", "encoding", false)
	}
	children = append(children, enc_codecinfo...)
	if len(v.CipheringAlgorithm) < 1 || len(v.CipheringAlgorithm) > 1 {
		if constraintErr := checkEncodedLength(opts, sbdb8a8_0, "51.5", "cipheringAlgorithm", "SIZE (1)", len(v.CipheringAlgorithm)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cipheringalgorithm, encodeErr_enc_cipheringalgorithm := ber.EncodeOctetString([]byte(v.CipheringAlgorithm))
	if encodeErr_enc_cipheringalgorithm != nil {
		return nil, qualifyBERError(encodeErr_enc_cipheringalgorithm, "cipheringAlgorithm", "encoding", false)
	}
	children = append(children, enc_cipheringalgorithm...)
	if v.GroupKeyNumberVkId != nil {
		if !(int64(*v.GroupKeyNumberVkId) >= 0 && int64(*v.GroupKeyNumberVkId) <= 15) {
			if constraintErr := checkEncodedValue(opts, sbdb8a8_0, "51.4", "groupKeyNumber-Vk-Id", "(0..15)", ber.ObserveInteger(int64(*v.GroupKeyNumberVkId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_groupkeynumbervkid := ber.EncodeInteger(int64(*v.GroupKeyNumberVkId))
		retagged_enc_groupkeynumbervkid, tagErr_enc_groupkeynumbervkid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_groupkeynumbervkid)
		if tagErr_enc_groupkeynumbervkid != nil {
			return nil, qualifyBERError(tagErr_enc_groupkeynumbervkid, "groupKeyNumber-Vk-Id", "encoding", false)
		}
		enc_groupkeynumbervkid = retagged_enc_groupkeynumbervkid
		children = append(children, enc_groupkeynumbervkid...)
	}
	if v.GroupKey != nil {
		if len(*v.GroupKey) < 8 || len(*v.GroupKey) > 8 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_0, "51.5", "groupKey", "SIZE (8)", len(*v.GroupKey)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_groupkey, encodeErr_enc_groupkey := ber.EncodeOctetString([]byte(*v.GroupKey))
		if encodeErr_enc_groupkey != nil {
			return nil, qualifyBERError(encodeErr_enc_groupkey, "groupKey", "encoding", false)
		}
		retagged_enc_groupkey, tagErr_enc_groupkey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_groupkey)
		if tagErr_enc_groupkey != nil {
			return nil, qualifyBERError(tagErr_enc_groupkey, "groupKey", "encoding", false)
		}
		enc_groupkey = retagged_enc_groupkey
		children = append(children, enc_groupkey...)
	}
	if v.Priority != nil {
		if !(int64(*v.Priority) >= 0 && int64(*v.Priority) <= 15) {
			if constraintErr := checkEncodedValue(opts, sbdb8a8_0, "51.4", "priority", "(0..15)", ber.ObserveInteger(int64(*v.Priority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_priority := ber.EncodeInteger(int64(*v.Priority))
		retagged_enc_priority, tagErr_enc_priority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_priority)
		if tagErr_enc_priority != nil {
			return nil, qualifyBERError(tagErr_enc_priority, "priority", "encoding", false)
		}
		enc_priority = retagged_enc_priority
		children = append(children, enc_priority...)
	}
	if v.UplinkFree != nil {
		enc_uplinkfree := ber.EncodeNull()
		retagged_enc_uplinkfree, tagErr_enc_uplinkfree := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_uplinkfree)
		if tagErr_enc_uplinkfree != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkfree, "uplinkFree", "encoding", false)
		}
		enc_uplinkfree = retagged_enc_uplinkfree
		children = append(children, enc_uplinkfree...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.Vstk != nil {
		if len(*v.Vstk) < 16 || len(*v.Vstk) > 16 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_0, "51.5", "vstk", "SIZE (16)", len(*v.Vstk)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vstk, encodeErr_enc_vstk := ber.EncodeOctetString([]byte(*v.Vstk))
		if encodeErr_enc_vstk != nil {
			return nil, qualifyBERError(encodeErr_enc_vstk, "vstk", "encoding", false)
		}
		retagged_enc_vstk, tagErr_enc_vstk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_vstk)
		if tagErr_enc_vstk != nil {
			return nil, qualifyBERError(tagErr_enc_vstk, "vstk", "encoding", false)
		}
		enc_vstk = retagged_enc_vstk
		children = append(children, enc_vstk...)
	}
	if v.VstkRand != nil {
		if len(*v.VstkRand) < 5 || len(*v.VstkRand) > 5 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_0, "51.5", "vstk-rand", "SIZE (5)", len(*v.VstkRand)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vstkrand, encodeErr_enc_vstkrand := ber.EncodeOctetString([]byte(*v.VstkRand))
		if encodeErr_enc_vstkrand != nil {
			return nil, qualifyBERError(encodeErr_enc_vstkrand, "vstk-rand", "encoding", false)
		}
		retagged_enc_vstkrand, tagErr_enc_vstkrand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_vstkrand)
		if tagErr_enc_vstkrand != nil {
			return nil, qualifyBERError(tagErr_enc_vstkrand, "vstk-rand", "encoding", false)
		}
		enc_vstkrand = retagged_enc_vstkrand
		children = append(children, enc_vstkrand...)
	}
	if v.TalkerChannelParameter != nil {
		enc_talkerchannelparameter := ber.EncodeNull()
		retagged_enc_talkerchannelparameter, tagErr_enc_talkerchannelparameter := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_talkerchannelparameter)
		if tagErr_enc_talkerchannelparameter != nil {
			return nil, qualifyBERError(tagErr_enc_talkerchannelparameter, "talkerChannelParameter", "encoding", false)
		}
		enc_talkerchannelparameter = retagged_enc_talkerchannelparameter
		children = append(children, enc_talkerchannelparameter...)
	}
	if v.UplinkReplyIndicator != nil {
		enc_uplinkreplyindicator := ber.EncodeNull()
		retagged_enc_uplinkreplyindicator, tagErr_enc_uplinkreplyindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_uplinkreplyindicator)
		if tagErr_enc_uplinkreplyindicator != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkreplyindicator, "uplinkReplyIndicator", "encoding", false)
		}
		enc_uplinkreplyindicator = retagged_enc_uplinkreplyindicator
		children = append(children, enc_uplinkreplyindicator...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sbdb8a8_0, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sbdb8a8_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PrepareGroupCallArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PrepareGroupCallArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PrepareGroupCallArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareGroupCallArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
		if constraintErr := checkEncodedLength(nil, sbdb8a8_0, "51.5", "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(v.Teleservice))
	if encodeErr_enc_teleservice != nil {
		return nil, qualifyBERError(encodeErr_enc_teleservice, "teleservice", "encoding", true)
	}
	children = append(children, enc_teleservice...)
	if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
		if constraintErr := checkEncodedLength(nil, sbdb8a8_0, "51.5", "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ascicallreference, encodeErr_enc_ascicallreference := ber.EncodeOctetString([]byte(v.AsciCallReference))
	if encodeErr_enc_ascicallreference != nil {
		return nil, qualifyBERError(encodeErr_enc_ascicallreference, "asciCallReference", "encoding", true)
	}
	children = append(children, enc_ascicallreference...)
	if len(v.CodecInfo) < 5 || len(v.CodecInfo) > 10 {
		if constraintErr := checkEncodedLength(nil, sbdb8a8_0, "51.5", "codec-Info", "SIZE (5..10)", len(v.CodecInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_codecinfo, encodeErr_enc_codecinfo := ber.EncodeOctetString([]byte(v.CodecInfo))
	if encodeErr_enc_codecinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_codecinfo, "codec-Info", "encoding", true)
	}
	children = append(children, enc_codecinfo...)
	if len(v.CipheringAlgorithm) < 1 || len(v.CipheringAlgorithm) > 1 {
		if constraintErr := checkEncodedLength(nil, sbdb8a8_0, "51.5", "cipheringAlgorithm", "SIZE (1)", len(v.CipheringAlgorithm)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cipheringalgorithm, encodeErr_enc_cipheringalgorithm := ber.EncodeOctetString([]byte(v.CipheringAlgorithm))
	if encodeErr_enc_cipheringalgorithm != nil {
		return nil, qualifyBERError(encodeErr_enc_cipheringalgorithm, "cipheringAlgorithm", "encoding", true)
	}
	children = append(children, enc_cipheringalgorithm...)
	if v.GroupKeyNumberVkId != nil {
		if !(int64(*v.GroupKeyNumberVkId) >= 0 && int64(*v.GroupKeyNumberVkId) <= 15) {
			if constraintErr := checkEncodedValue(nil, sbdb8a8_0, "51.4", "groupKeyNumber-Vk-Id", "(0..15)", ber.ObserveInteger(int64(*v.GroupKeyNumberVkId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_groupkeynumbervkid := ber.EncodeInteger(int64(*v.GroupKeyNumberVkId))
		retagged_enc_groupkeynumbervkid, tagErr_enc_groupkeynumbervkid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_groupkeynumbervkid)
		if tagErr_enc_groupkeynumbervkid != nil {
			return nil, qualifyBERError(tagErr_enc_groupkeynumbervkid, "groupKeyNumber-Vk-Id", "encoding", true)
		}
		enc_groupkeynumbervkid = retagged_enc_groupkeynumbervkid
		children = append(children, enc_groupkeynumbervkid...)
	}
	if v.GroupKey != nil {
		if len(*v.GroupKey) < 8 || len(*v.GroupKey) > 8 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_0, "51.5", "groupKey", "SIZE (8)", len(*v.GroupKey)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_groupkey, encodeErr_enc_groupkey := ber.EncodeOctetString([]byte(*v.GroupKey))
		if encodeErr_enc_groupkey != nil {
			return nil, qualifyBERError(encodeErr_enc_groupkey, "groupKey", "encoding", true)
		}
		retagged_enc_groupkey, tagErr_enc_groupkey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_groupkey)
		if tagErr_enc_groupkey != nil {
			return nil, qualifyBERError(tagErr_enc_groupkey, "groupKey", "encoding", true)
		}
		enc_groupkey = retagged_enc_groupkey
		children = append(children, enc_groupkey...)
	}
	if v.Priority != nil {
		if !(int64(*v.Priority) >= 0 && int64(*v.Priority) <= 15) {
			if constraintErr := checkEncodedValue(nil, sbdb8a8_0, "51.4", "priority", "(0..15)", ber.ObserveInteger(int64(*v.Priority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_priority := ber.EncodeInteger(int64(*v.Priority))
		retagged_enc_priority, tagErr_enc_priority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_priority)
		if tagErr_enc_priority != nil {
			return nil, qualifyBERError(tagErr_enc_priority, "priority", "encoding", true)
		}
		enc_priority = retagged_enc_priority
		children = append(children, enc_priority...)
	}
	if v.UplinkFree != nil {
		enc_uplinkfree := ber.EncodeNull()
		retagged_enc_uplinkfree, tagErr_enc_uplinkfree := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_uplinkfree)
		if tagErr_enc_uplinkfree != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkfree, "uplinkFree", "encoding", true)
		}
		enc_uplinkfree = retagged_enc_uplinkfree
		children = append(children, enc_uplinkfree...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.Vstk != nil {
		if len(*v.Vstk) < 16 || len(*v.Vstk) > 16 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_0, "51.5", "vstk", "SIZE (16)", len(*v.Vstk)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vstk, encodeErr_enc_vstk := ber.EncodeOctetString([]byte(*v.Vstk))
		if encodeErr_enc_vstk != nil {
			return nil, qualifyBERError(encodeErr_enc_vstk, "vstk", "encoding", true)
		}
		retagged_enc_vstk, tagErr_enc_vstk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_vstk)
		if tagErr_enc_vstk != nil {
			return nil, qualifyBERError(tagErr_enc_vstk, "vstk", "encoding", true)
		}
		enc_vstk = retagged_enc_vstk
		children = append(children, enc_vstk...)
	}
	if v.VstkRand != nil {
		if len(*v.VstkRand) < 5 || len(*v.VstkRand) > 5 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_0, "51.5", "vstk-rand", "SIZE (5)", len(*v.VstkRand)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vstkrand, encodeErr_enc_vstkrand := ber.EncodeOctetString([]byte(*v.VstkRand))
		if encodeErr_enc_vstkrand != nil {
			return nil, qualifyBERError(encodeErr_enc_vstkrand, "vstk-rand", "encoding", true)
		}
		retagged_enc_vstkrand, tagErr_enc_vstkrand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_vstkrand)
		if tagErr_enc_vstkrand != nil {
			return nil, qualifyBERError(tagErr_enc_vstkrand, "vstk-rand", "encoding", true)
		}
		enc_vstkrand = retagged_enc_vstkrand
		children = append(children, enc_vstkrand...)
	}
	if v.TalkerChannelParameter != nil {
		enc_talkerchannelparameter := ber.EncodeNull()
		retagged_enc_talkerchannelparameter, tagErr_enc_talkerchannelparameter := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_talkerchannelparameter)
		if tagErr_enc_talkerchannelparameter != nil {
			return nil, qualifyBERError(tagErr_enc_talkerchannelparameter, "talkerChannelParameter", "encoding", true)
		}
		enc_talkerchannelparameter = retagged_enc_talkerchannelparameter
		children = append(children, enc_talkerchannelparameter...)
	}
	if v.UplinkReplyIndicator != nil {
		enc_uplinkreplyindicator := ber.EncodeNull()
		retagged_enc_uplinkreplyindicator, tagErr_enc_uplinkreplyindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_uplinkreplyindicator)
		if tagErr_enc_uplinkreplyindicator != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkreplyindicator, "uplinkReplyIndicator", "encoding", true)
		}
		enc_uplinkreplyindicator = retagged_enc_uplinkreplyindicator
		children = append(children, enc_uplinkreplyindicator...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sbdb8a8_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sbdb8a8_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding PrepareGroupCallArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PrepareGroupCallArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PrepareGroupCallArg from BER/DER format.
func (destination *PrepareGroupCallArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PrepareGroupCallArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(PrepareGroupCallArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sbdb8a8_0, "child", (*PrepareGroupCallArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PrepareGroupCallArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PrepareGroupCallArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PrepareGroupCallArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareGroupCallArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode teleservice
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field teleservice", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "teleservice", content[offset:])
		val_teleservice, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "teleservice", "decoding", false)
		}
		v.Teleservice = ExtTeleserviceCode(val_teleservice)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
			if constraintErr := checkDecodedLength(opts, sbdb8a8_0, "51.5", "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode asciCallReference
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field asciCallReference", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "asciCallReference", content[offset:])
		val_ascicallreference, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "asciCallReference", "decoding", false)
		}
		v.AsciCallReference = ASCICallReference(val_ascicallreference)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
			if constraintErr := checkDecodedLength(opts, sbdb8a8_0, "51.5", "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode codec-Info
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field codec-Info", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "codec-Info", content[offset:])
		val_codecinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "codec-Info", "decoding", false)
		}
		v.CodecInfo = CODECInfo(val_codecinfo)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.CodecInfo) < 5 || len(v.CodecInfo) > 10 {
			if constraintErr := checkDecodedLength(opts, sbdb8a8_0, "51.5", "codec-Info", "SIZE (5..10)", len(v.CodecInfo)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cipheringAlgorithm
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cipheringAlgorithm", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cipheringAlgorithm", content[offset:])
		val_cipheringalgorithm, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cipheringAlgorithm", "decoding", false)
		}
		v.CipheringAlgorithm = CipheringAlgorithm(val_cipheringalgorithm)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.CipheringAlgorithm) < 1 || len(v.CipheringAlgorithm) > 1 {
			if constraintErr := checkDecodedLength(opts, sbdb8a8_0, "51.5", "cipheringAlgorithm", "SIZE (1)", len(v.CipheringAlgorithm)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode groupKeyNumber-Vk-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "groupKeyNumber-Vk-Id", content[offset:])
				decodedTag_groupkeynumbervkid, n_groupkeynumbervkid, rawVal_groupkeynumbervkid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "groupKeyNumber-Vk-Id", "decoding", false)
				}
				if decodedTag_groupkeynumbervkid.Class != tag.ClassContextSpecific || decodedTag_groupkeynumbervkid.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_groupkeynumbervkid), "groupKeyNumber-Vk-Id", "decoding", false)
				}
				if decodedTag_groupkeynumbervkid.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_groupkeynumbervkid), "groupKeyNumber-Vk-Id", "decoding", false)
				}
				decVal_groupkeynumbervkid, intErr := ber.DecodeIntegerValue(rawVal_groupkeynumbervkid)
				if intErr != nil {
					return qualifyBERError(intErr, "groupKeyNumber-Vk-Id", "decoding", false)
				}
				tmp_groupkeynumbervkid := GroupKeyNumber(decVal_groupkeynumbervkid)
				v.GroupKeyNumberVkId = &tmp_groupkeynumbervkid
				if offset < 0 || offset >
					len(content) || n_groupkeynumbervkid < 0 || n_groupkeynumbervkid >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_groupkeynumbervkid
				if !(int64(*v.GroupKeyNumberVkId) >= 0 && int64(*v.GroupKeyNumberVkId) <= 15) {
					if constraintErr := checkDecodedValue(opts, sbdb8a8_0, "51.4", "groupKeyNumber-Vk-Id", "(0..15)", ber.ObserveInteger(int64(*v.GroupKeyNumberVkId))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode groupKey
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "groupKey", content[offset:])
				decodedTag_groupkey, n_groupkey, rawVal_groupkey, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "groupKey", "decoding", false)
				}
				if decodedTag_groupkey.Class != tag.ClassContextSpecific || decodedTag_groupkey.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_groupkey), "groupKey", "decoding", false)
				}
				decVal_groupkey, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_groupkey.Constructed, rawVal_groupkey, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "groupKey", "decoding", false)
				}
				tmp_groupkey := Kc(decVal_groupkey)
				v.GroupKey = &tmp_groupkey
				if offset < 0 || offset >
					len(content) || n_groupkey < 0 || n_groupkey > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_groupkey
				if len(*v.GroupKey) < 8 || len(*v.GroupKey) > 8 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_0, "51.5", "groupKey", "SIZE (8)", len(*v.GroupKey)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode priority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "priority", content[offset:])
				decodedTag_priority, n_priority, rawVal_priority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "priority", "decoding", false)
				}
				if decodedTag_priority.Class != tag.ClassContextSpecific || decodedTag_priority.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_priority), "priority", "decoding", false)
				}
				if decodedTag_priority.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_priority), "priority", "decoding", false)
				}
				decVal_priority, intErr := ber.DecodeIntegerValue(rawVal_priority)
				if intErr != nil {
					return qualifyBERError(intErr, "priority", "decoding", false)
				}
				tmp_priority := EMLPPPriority(decVal_priority)
				v.Priority = &tmp_priority
				if offset < 0 || offset >
					len(content) || n_priority < 0 || n_priority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_priority
				if !(int64(*v.Priority) >= 0 && int64(*v.Priority) <= 15) {
					if constraintErr := checkDecodedValue(opts, sbdb8a8_0, "51.4", "priority", "(0..15)", ber.ObserveInteger(int64(*v.Priority))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode uplinkFree
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "uplinkFree", content[offset:])
				decodedTag_uplinkfree, n_uplinkfree, rawVal_uplinkfree, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uplinkFree", "decoding", false)
				}
				if decodedTag_uplinkfree.Class != tag.ClassContextSpecific || decodedTag_uplinkfree.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_uplinkfree), "uplinkFree", "decoding", false)
				}
				if decodedTag_uplinkfree.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_uplinkfree), "uplinkFree", "decoding", false)
				}
				if len(rawVal_uplinkfree) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkfree)), "uplinkFree", "decoding", false)
				}
				v.UplinkFree = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_uplinkfree < 0 || n_uplinkfree > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uplinkfree
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
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
	// Decode vstk
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "vstk", content[offset:])
				decodedTag_vstk, n_vstk, rawVal_vstk, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "vstk", "decoding", false)
				}
				if decodedTag_vstk.Class != tag.ClassContextSpecific || decodedTag_vstk.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_vstk), "vstk", "decoding", false)
				}
				decVal_vstk, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_vstk.Constructed, rawVal_vstk, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "vstk", "decoding", false)
				}
				tmp_vstk := VSTK(decVal_vstk)
				v.Vstk = &tmp_vstk
				if offset < 0 || offset >
					len(content) || n_vstk < 0 || n_vstk > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_vstk
				if len(*v.Vstk) < 16 || len(*v.Vstk) > 16 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_0, "51.5", "vstk", "SIZE (16)", len(*v.Vstk)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode vstk-rand
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "vstk-rand", content[offset:])
				decodedTag_vstkrand, n_vstkrand, rawVal_vstkrand, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "vstk-rand", "decoding", false)
				}
				if decodedTag_vstkrand.Class != tag.ClassContextSpecific || decodedTag_vstkrand.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_vstkrand), "vstk-rand", "decoding", false)
				}
				decVal_vstkrand, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_vstkrand.Constructed, rawVal_vstkrand, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "vstk-rand", "decoding", false)
				}
				tmp_vstkrand := VSTKRAND(decVal_vstkrand)
				v.VstkRand = &tmp_vstkrand
				if offset < 0 || offset >
					len(content) || n_vstkrand < 0 || n_vstkrand > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_vstkrand
				if len(*v.VstkRand) < 5 || len(*v.VstkRand) > 5 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_0, "51.5", "vstk-rand", "SIZE (5)", len(*v.VstkRand)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode talkerChannelParameter
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "talkerChannelParameter", content[offset:])
				decodedTag_talkerchannelparameter, n_talkerchannelparameter, rawVal_talkerchannelparameter, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "talkerChannelParameter", "decoding", false)
				}
				if decodedTag_talkerchannelparameter.Class != tag.ClassContextSpecific || decodedTag_talkerchannelparameter.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_talkerchannelparameter), "talkerChannelParameter", "decoding", false)
				}
				if decodedTag_talkerchannelparameter.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_talkerchannelparameter), "talkerChannelParameter", "decoding", false)
				}
				if len(rawVal_talkerchannelparameter) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_talkerchannelparameter)), "talkerChannelParameter", "decoding", false)
				}
				v.TalkerChannelParameter = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_talkerchannelparameter < 0 || n_talkerchannelparameter >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_talkerchannelparameter
			}
		}
	}
	// Decode uplinkReplyIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "uplinkReplyIndicator", content[offset:])
				decodedTag_uplinkreplyindicator, n_uplinkreplyindicator, rawVal_uplinkreplyindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uplinkReplyIndicator", "decoding", false)
				}
				if decodedTag_uplinkreplyindicator.Class != tag.ClassContextSpecific || decodedTag_uplinkreplyindicator.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_uplinkreplyindicator), "uplinkReplyIndicator", "decoding", false)
				}
				if decodedTag_uplinkreplyindicator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_uplinkreplyindicator), "uplinkReplyIndicator", "decoding", false)
				}
				if len(rawVal_uplinkreplyindicator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkreplyindicator)), "uplinkReplyIndicator", "decoding", false)
				}
				v.UplinkReplyIndicator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_uplinkreplyindicator < 0 || n_uplinkreplyindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uplinkreplyindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareGroupCallArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "PrepareGroupCallArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sbdb8a8_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes PrepareGroupCallRes to BER format.
func (v *PrepareGroupCallRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PrepareGroupCallRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PrepareGroupCallRes).MarshalBER, (*PrepareGroupCallRes).marshalBER, 3)

}
func (v *PrepareGroupCallRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 9 {
		if constraintErr := checkEncodedLength(opts, sbdb8a8_1, "51.5", "groupCallNumber", "SIZE (1..9)", len(v.GroupCallNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, sbdb8a8_1, "51.5", "groupCallNumber", "SIZE (1..20)", len(v.GroupCallNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_groupcallnumber, encodeErr_enc_groupcallnumber := ber.EncodeOctetString([]byte(v.GroupCallNumber))
	if encodeErr_enc_groupcallnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_groupcallnumber, "groupCallNumber", "encoding", false)
	}
	children = append(children, enc_groupcallnumber...)
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
		if err := checkOpaqueAddition(ext, opts, sbdb8a8_1, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sbdb8a8_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PrepareGroupCallRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PrepareGroupCallRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PrepareGroupCallRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareGroupCallRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 9 {
		if constraintErr := checkEncodedLength(nil, sbdb8a8_1, "51.5", "groupCallNumber", "SIZE (1..9)", len(v.GroupCallNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, sbdb8a8_1, "51.5", "groupCallNumber", "SIZE (1..20)", len(v.GroupCallNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_groupcallnumber, encodeErr_enc_groupcallnumber := ber.EncodeOctetString([]byte(v.GroupCallNumber))
	if encodeErr_enc_groupcallnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_groupcallnumber, "groupCallNumber", "encoding", true)
	}
	children = append(children, enc_groupcallnumber...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sbdb8a8_1, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sbdb8a8_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding PrepareGroupCallRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PrepareGroupCallRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PrepareGroupCallRes from BER/DER format.
func (destination *PrepareGroupCallRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PrepareGroupCallRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(PrepareGroupCallRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sbdb8a8_1, "child", (*PrepareGroupCallRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PrepareGroupCallRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PrepareGroupCallRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PrepareGroupCallRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareGroupCallRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode groupCallNumber
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field groupCallNumber", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "groupCallNumber", content[offset:])
		val_groupcallnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "groupCallNumber", "decoding", false)
		}
		v.GroupCallNumber = ISDNAddressString(val_groupcallnumber)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 9 {
			if constraintErr := checkDecodedLength(opts, sbdb8a8_1, "51.5", "groupCallNumber", "SIZE (1..9)", len(v.GroupCallNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, sbdb8a8_1, "51.5", "groupCallNumber", "SIZE (1..20)", len(v.GroupCallNumber)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareGroupCallRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "PrepareGroupCallRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sbdb8a8_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SendGroupCallEndSignalArg to BER format.
func (v *SendGroupCallEndSignalArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallEndSignalArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendGroupCallEndSignalArg).MarshalBER, (*SendGroupCallEndSignalArg).marshalBER, 3)

}
func (v *SendGroupCallEndSignalArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_2, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		children = append(children, enc_imsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := checkEncodedValue(opts, sbdb8a8_2, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, qualifyBERError(tagErr_enc_talkerpriority, "talkerPriority", "encoding", false)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalInfo", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_2, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, ber.UnusedBitCount(v.AdditionalInfo.BitLength))
		if encodeErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalinfo, "additionalInfo", "encoding", false)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalinfo, "additionalInfo", "encoding", false)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sbdb8a8_2, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sbdb8a8_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendGroupCallEndSignalArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendGroupCallEndSignalArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendGroupCallEndSignalArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallEndSignalArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_2, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		children = append(children, enc_imsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := checkEncodedValue(nil, sbdb8a8_2, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, qualifyBERError(tagErr_enc_talkerpriority, "talkerPriority", "encoding", true)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalInfo", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_2, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, ber.UnusedBitCount(v.AdditionalInfo.BitLength))
		if encodeErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalinfo, "additionalInfo", "encoding", true)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalinfo, "additionalInfo", "encoding", true)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sbdb8a8_2, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sbdb8a8_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SendGroupCallEndSignalArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendGroupCallEndSignalArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendGroupCallEndSignalArg from BER/DER format.
func (destination *SendGroupCallEndSignalArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendGroupCallEndSignalArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendGroupCallEndSignalArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sbdb8a8_2, "child", (*SendGroupCallEndSignalArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendGroupCallEndSignalArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendGroupCallEndSignalArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendGroupCallEndSignalArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendGroupCallEndSignalArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(val_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_2, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
	// Decode talkerPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "talkerPriority", content[offset:])
				decodedTag_talkerpriority, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "talkerPriority", "decoding", false)
				}
				if decodedTag_talkerpriority.Class != tag.ClassContextSpecific || decodedTag_talkerpriority.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_talkerpriority), "talkerPriority", "decoding", false)
				}
				if decodedTag_talkerpriority.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_talkerpriority), "talkerPriority", "decoding", false)
				}
				decVal_talkerpriority, intErr := ber.DecodeEnumeratedValue(rawVal_talkerpriority)
				if intErr != nil {
					return qualifyBERError(intErr, "talkerPriority", "decoding", false)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				if offset < 0 || offset >
					len(content) || n_talkerpriority < 0 || n_talkerpriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_talkerpriority
				if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
					if constraintErr := checkDecodedValue(opts, sbdb8a8_2, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additionalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "additionalInfo", content[offset:])
				decodedTag_additionalinfo, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalInfo", "decoding", false)
				}
				if decodedTag_additionalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalinfo.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_additionalinfo), "additionalInfo", "decoding", false)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalinfo.Constructed, rawVal_additionalinfo, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "additionalInfo", "decoding", false)
				}
				bsBitLength_additionalinfo, bsLenErr_additionalinfo := ber.BitStringBitLength(len(bsBytes_additionalinfo), bsUnused_additionalinfo)
				if bsLenErr_additionalinfo != nil {
					return qualifyBERError(bsLenErr_additionalinfo, "additionalInfo", "decoding", false)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: bsBitLength_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				if offset < 0 || offset >
					len(content) || n_additionalinfo < 0 || n_additionalinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalinfo
				if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_2, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallEndSignalArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallEndSignalArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sbdb8a8_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SendGroupCallEndSignalRes to BER format.
func (v *SendGroupCallEndSignalRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallEndSignalRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendGroupCallEndSignalRes).MarshalBER, (*SendGroupCallEndSignalRes).marshalBER, 3)

}
func (v *SendGroupCallEndSignalRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		if err := checkOpaqueAddition(ext, opts, sbdb8a8_3, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sbdb8a8_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendGroupCallEndSignalRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendGroupCallEndSignalRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendGroupCallEndSignalRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallEndSignalRes receiver is nil", ber.ErrInvalidValue)
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
			return nil, invalidDERAddition(ext, sbdb8a8_3, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sbdb8a8_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SendGroupCallEndSignalRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendGroupCallEndSignalRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendGroupCallEndSignalRes from BER/DER format.
func (destination *SendGroupCallEndSignalRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendGroupCallEndSignalRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendGroupCallEndSignalRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sbdb8a8_3, "child", (*SendGroupCallEndSignalRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendGroupCallEndSignalRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendGroupCallEndSignalRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendGroupCallEndSignalRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendGroupCallEndSignalRes", Cause: ber.ErrExtraData}
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
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallEndSignalRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallEndSignalRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sbdb8a8_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ForwardGroupCallSignallingArg to BER format.
func (v *ForwardGroupCallSignallingArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ForwardGroupCallSignallingArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ForwardGroupCallSignallingArg).MarshalBER, (*ForwardGroupCallSignallingArg).marshalBER, 3)

}
func (v *ForwardGroupCallSignallingArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_4, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		children = append(children, enc_imsi...)
	}
	if v.UplinkRequestAck != nil {
		enc_uplinkrequestack := ber.EncodeNull()
		retagged_enc_uplinkrequestack, tagErr_enc_uplinkrequestack := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_uplinkrequestack)
		if tagErr_enc_uplinkrequestack != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkrequestack, "uplinkRequestAck", "encoding", false)
		}
		enc_uplinkrequestack = retagged_enc_uplinkrequestack
		children = append(children, enc_uplinkrequestack...)
	}
	if v.UplinkReleaseIndication != nil {
		enc_uplinkreleaseindication := ber.EncodeNull()
		retagged_enc_uplinkreleaseindication, tagErr_enc_uplinkreleaseindication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uplinkreleaseindication)
		if tagErr_enc_uplinkreleaseindication != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkreleaseindication, "uplinkReleaseIndication", "encoding", false)
		}
		enc_uplinkreleaseindication = retagged_enc_uplinkreleaseindication
		children = append(children, enc_uplinkreleaseindication...)
	}
	if v.UplinkRejectCommand != nil {
		enc_uplinkrejectcommand := ber.EncodeNull()
		retagged_enc_uplinkrejectcommand, tagErr_enc_uplinkrejectcommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_uplinkrejectcommand)
		if tagErr_enc_uplinkrejectcommand != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkrejectcommand, "uplinkRejectCommand", "encoding", false)
		}
		enc_uplinkrejectcommand = retagged_enc_uplinkrejectcommand
		children = append(children, enc_uplinkrejectcommand...)
	}
	if v.UplinkSeizedCommand != nil {
		enc_uplinkseizedcommand := ber.EncodeNull()
		retagged_enc_uplinkseizedcommand, tagErr_enc_uplinkseizedcommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_uplinkseizedcommand)
		if tagErr_enc_uplinkseizedcommand != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkseizedcommand, "uplinkSeizedCommand", "encoding", false)
		}
		enc_uplinkseizedcommand = retagged_enc_uplinkseizedcommand
		children = append(children, enc_uplinkseizedcommand...)
	}
	if v.UplinkReleaseCommand != nil {
		enc_uplinkreleasecommand := ber.EncodeNull()
		retagged_enc_uplinkreleasecommand, tagErr_enc_uplinkreleasecommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_uplinkreleasecommand)
		if tagErr_enc_uplinkreleasecommand != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkreleasecommand, "uplinkReleaseCommand", "encoding", false)
		}
		enc_uplinkreleasecommand = retagged_enc_uplinkreleasecommand
		children = append(children, enc_uplinkreleasecommand...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.StateAttributes != nil {
		enc_stateattributes, err := v.StateAttributes.MarshalBER(ber.ChildEncodeOptions(opts, "stateAttributes")...)
		if err != nil {
			return nil, qualifyBERError(err, "stateAttributes", "encoding", false)
		}
		retagged_enc_stateattributes, tagErr_enc_stateattributes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_stateattributes)
		if tagErr_enc_stateattributes != nil {
			return nil, qualifyBERError(tagErr_enc_stateattributes, "stateAttributes", "encoding", false)
		}
		enc_stateattributes = retagged_enc_stateattributes
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_stateattributes)
		children = append(children, enc_stateattributes...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := checkEncodedValue(opts, sbdb8a8_4, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, qualifyBERError(tagErr_enc_talkerpriority, "talkerPriority", "encoding", false)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalInfo", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_4, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, ber.UnusedBitCount(v.AdditionalInfo.BitLength))
		if encodeErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalinfo, "additionalInfo", "encoding", false)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalinfo, "additionalInfo", "encoding", false)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.EmergencyModeResetCommandFlag != nil {
		enc_emergencymoderesetcommandflag := ber.EncodeNull()
		retagged_enc_emergencymoderesetcommandflag, tagErr_enc_emergencymoderesetcommandflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_emergencymoderesetcommandflag)
		if tagErr_enc_emergencymoderesetcommandflag != nil {
			return nil, qualifyBERError(tagErr_enc_emergencymoderesetcommandflag, "emergencyModeResetCommandFlag", "encoding", false)
		}
		enc_emergencymoderesetcommandflag = retagged_enc_emergencymoderesetcommandflag
		children = append(children, enc_emergencymoderesetcommandflag...)
	}
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_4, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		if encodeErr_enc_smrpui != nil {
			return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", false)
		}
		retagged_enc_smrpui, tagErr_enc_smrpui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_smrpui)
		if tagErr_enc_smrpui != nil {
			return nil, qualifyBERError(tagErr_enc_smrpui, "sm-RP-UI", "encoding", false)
		}
		enc_smrpui = retagged_enc_smrpui
		children = append(children, enc_smrpui...)
	}
	if v.AnAPDU != nil {
		enc_anapdu, err := v.AnAPDU.MarshalBER(ber.ChildEncodeOptions(opts, "an-APDU")...)
		if err != nil {
			return nil, qualifyBERError(err, "an-APDU", "encoding", false)
		}
		retagged_enc_anapdu, tagErr_enc_anapdu := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_anapdu)
		if tagErr_enc_anapdu != nil {
			return nil, qualifyBERError(tagErr_enc_anapdu, "an-APDU", "encoding", false)
		}
		enc_anapdu = retagged_enc_anapdu
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_anapdu)
		children = append(children, enc_anapdu...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sbdb8a8_4, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sbdb8a8_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ForwardGroupCallSignallingArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ForwardGroupCallSignallingArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ForwardGroupCallSignallingArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardGroupCallSignallingArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_4, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		children = append(children, enc_imsi...)
	}
	if v.UplinkRequestAck != nil {
		enc_uplinkrequestack := ber.EncodeNull()
		retagged_enc_uplinkrequestack, tagErr_enc_uplinkrequestack := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_uplinkrequestack)
		if tagErr_enc_uplinkrequestack != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkrequestack, "uplinkRequestAck", "encoding", true)
		}
		enc_uplinkrequestack = retagged_enc_uplinkrequestack
		children = append(children, enc_uplinkrequestack...)
	}
	if v.UplinkReleaseIndication != nil {
		enc_uplinkreleaseindication := ber.EncodeNull()
		retagged_enc_uplinkreleaseindication, tagErr_enc_uplinkreleaseindication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uplinkreleaseindication)
		if tagErr_enc_uplinkreleaseindication != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkreleaseindication, "uplinkReleaseIndication", "encoding", true)
		}
		enc_uplinkreleaseindication = retagged_enc_uplinkreleaseindication
		children = append(children, enc_uplinkreleaseindication...)
	}
	if v.UplinkRejectCommand != nil {
		enc_uplinkrejectcommand := ber.EncodeNull()
		retagged_enc_uplinkrejectcommand, tagErr_enc_uplinkrejectcommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_uplinkrejectcommand)
		if tagErr_enc_uplinkrejectcommand != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkrejectcommand, "uplinkRejectCommand", "encoding", true)
		}
		enc_uplinkrejectcommand = retagged_enc_uplinkrejectcommand
		children = append(children, enc_uplinkrejectcommand...)
	}
	if v.UplinkSeizedCommand != nil {
		enc_uplinkseizedcommand := ber.EncodeNull()
		retagged_enc_uplinkseizedcommand, tagErr_enc_uplinkseizedcommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_uplinkseizedcommand)
		if tagErr_enc_uplinkseizedcommand != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkseizedcommand, "uplinkSeizedCommand", "encoding", true)
		}
		enc_uplinkseizedcommand = retagged_enc_uplinkseizedcommand
		children = append(children, enc_uplinkseizedcommand...)
	}
	if v.UplinkReleaseCommand != nil {
		enc_uplinkreleasecommand := ber.EncodeNull()
		retagged_enc_uplinkreleasecommand, tagErr_enc_uplinkreleasecommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_uplinkreleasecommand)
		if tagErr_enc_uplinkreleasecommand != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkreleasecommand, "uplinkReleaseCommand", "encoding", true)
		}
		enc_uplinkreleasecommand = retagged_enc_uplinkreleasecommand
		children = append(children, enc_uplinkreleasecommand...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.StateAttributes != nil {
		enc_stateattributes, err := v.StateAttributes.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "stateAttributes", "encoding", true)
		}
		retagged_enc_stateattributes, tagErr_enc_stateattributes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_stateattributes)
		if tagErr_enc_stateattributes != nil {
			return nil, qualifyBERError(tagErr_enc_stateattributes, "stateAttributes", "encoding", true)
		}
		enc_stateattributes = retagged_enc_stateattributes
		children = append(children, enc_stateattributes...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := checkEncodedValue(nil, sbdb8a8_4, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, qualifyBERError(tagErr_enc_talkerpriority, "talkerPriority", "encoding", true)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalInfo", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_4, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, ber.UnusedBitCount(v.AdditionalInfo.BitLength))
		if encodeErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalinfo, "additionalInfo", "encoding", true)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalinfo, "additionalInfo", "encoding", true)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.EmergencyModeResetCommandFlag != nil {
		enc_emergencymoderesetcommandflag := ber.EncodeNull()
		retagged_enc_emergencymoderesetcommandflag, tagErr_enc_emergencymoderesetcommandflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_emergencymoderesetcommandflag)
		if tagErr_enc_emergencymoderesetcommandflag != nil {
			return nil, qualifyBERError(tagErr_enc_emergencymoderesetcommandflag, "emergencyModeResetCommandFlag", "encoding", true)
		}
		enc_emergencymoderesetcommandflag = retagged_enc_emergencymoderesetcommandflag
		children = append(children, enc_emergencymoderesetcommandflag...)
	}
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_4, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		if encodeErr_enc_smrpui != nil {
			return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", true)
		}
		retagged_enc_smrpui, tagErr_enc_smrpui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_smrpui)
		if tagErr_enc_smrpui != nil {
			return nil, qualifyBERError(tagErr_enc_smrpui, "sm-RP-UI", "encoding", true)
		}
		enc_smrpui = retagged_enc_smrpui
		children = append(children, enc_smrpui...)
	}
	if v.AnAPDU != nil {
		enc_anapdu, err := v.AnAPDU.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "an-APDU", "encoding", true)
		}
		retagged_enc_anapdu, tagErr_enc_anapdu := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_anapdu)
		if tagErr_enc_anapdu != nil {
			return nil, qualifyBERError(tagErr_enc_anapdu, "an-APDU", "encoding", true)
		}
		enc_anapdu = retagged_enc_anapdu
		children = append(children, enc_anapdu...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sbdb8a8_4, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sbdb8a8_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ForwardGroupCallSignallingArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ForwardGroupCallSignallingArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ForwardGroupCallSignallingArg from BER/DER format.
func (destination *ForwardGroupCallSignallingArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ForwardGroupCallSignallingArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ForwardGroupCallSignallingArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sbdb8a8_4, "child", (*ForwardGroupCallSignallingArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ForwardGroupCallSignallingArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ForwardGroupCallSignallingArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ForwardGroupCallSignallingArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardGroupCallSignallingArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(val_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_4, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode uplinkRequestAck
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "uplinkRequestAck", content[offset:])
				decodedTag_uplinkrequestack, n_uplinkrequestack, rawVal_uplinkrequestack, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uplinkRequestAck", "decoding", false)
				}
				if decodedTag_uplinkrequestack.Class != tag.ClassContextSpecific || decodedTag_uplinkrequestack.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_uplinkrequestack), "uplinkRequestAck", "decoding", false)
				}
				if decodedTag_uplinkrequestack.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_uplinkrequestack), "uplinkRequestAck", "decoding", false)
				}
				if len(rawVal_uplinkrequestack) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkrequestack)), "uplinkRequestAck", "decoding", false)
				}
				v.UplinkRequestAck = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_uplinkrequestack < 0 || n_uplinkrequestack > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uplinkrequestack
			}
		}
	}
	// Decode uplinkReleaseIndication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "uplinkReleaseIndication", content[offset:])
				decodedTag_uplinkreleaseindication, n_uplinkreleaseindication, rawVal_uplinkreleaseindication, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uplinkReleaseIndication", "decoding", false)
				}
				if decodedTag_uplinkreleaseindication.Class != tag.ClassContextSpecific || decodedTag_uplinkreleaseindication.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_uplinkreleaseindication), "uplinkReleaseIndication", "decoding", false)
				}
				if decodedTag_uplinkreleaseindication.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_uplinkreleaseindication), "uplinkReleaseIndication", "decoding", false)
				}
				if len(rawVal_uplinkreleaseindication) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkreleaseindication)), "uplinkReleaseIndication", "decoding", false)
				}
				v.UplinkReleaseIndication = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_uplinkreleaseindication < 0 || n_uplinkreleaseindication >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uplinkreleaseindication
			}
		}
	}
	// Decode uplinkRejectCommand
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "uplinkRejectCommand", content[offset:])
				decodedTag_uplinkrejectcommand, n_uplinkrejectcommand, rawVal_uplinkrejectcommand, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uplinkRejectCommand", "decoding", false)
				}
				if decodedTag_uplinkrejectcommand.Class != tag.ClassContextSpecific || decodedTag_uplinkrejectcommand.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_uplinkrejectcommand), "uplinkRejectCommand", "decoding", false)
				}
				if decodedTag_uplinkrejectcommand.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_uplinkrejectcommand), "uplinkRejectCommand", "decoding", false)
				}
				if len(rawVal_uplinkrejectcommand) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkrejectcommand)), "uplinkRejectCommand", "decoding", false)
				}
				v.UplinkRejectCommand = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_uplinkrejectcommand < 0 || n_uplinkrejectcommand > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uplinkrejectcommand
			}
		}
	}
	// Decode uplinkSeizedCommand
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "uplinkSeizedCommand", content[offset:])
				decodedTag_uplinkseizedcommand, n_uplinkseizedcommand, rawVal_uplinkseizedcommand, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uplinkSeizedCommand", "decoding", false)
				}
				if decodedTag_uplinkseizedcommand.Class != tag.ClassContextSpecific || decodedTag_uplinkseizedcommand.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_uplinkseizedcommand), "uplinkSeizedCommand", "decoding", false)
				}
				if decodedTag_uplinkseizedcommand.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_uplinkseizedcommand), "uplinkSeizedCommand", "decoding", false)
				}
				if len(rawVal_uplinkseizedcommand) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkseizedcommand)), "uplinkSeizedCommand", "decoding", false)
				}
				v.UplinkSeizedCommand = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_uplinkseizedcommand < 0 || n_uplinkseizedcommand > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uplinkseizedcommand
			}
		}
	}
	// Decode uplinkReleaseCommand
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "uplinkReleaseCommand", content[offset:])
				decodedTag_uplinkreleasecommand, n_uplinkreleasecommand, rawVal_uplinkreleasecommand, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uplinkReleaseCommand", "decoding", false)
				}
				if decodedTag_uplinkreleasecommand.Class != tag.ClassContextSpecific || decodedTag_uplinkreleasecommand.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_uplinkreleasecommand), "uplinkReleaseCommand", "decoding", false)
				}
				if decodedTag_uplinkreleasecommand.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_uplinkreleasecommand), "uplinkReleaseCommand", "decoding", false)
				}
				if len(rawVal_uplinkreleasecommand) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkreleasecommand)), "uplinkReleaseCommand", "decoding", false)
				}
				v.UplinkReleaseCommand = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_uplinkreleasecommand < 0 || n_uplinkreleasecommand >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uplinkreleasecommand
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
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode stateAttributes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "stateAttributes", content[offset:])
				decodedTag_stateattributes, n_stateattributes, rawVal_stateattributes, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "stateAttributes", "decoding", false)
				}
				if decodedTag_stateattributes.Class != tag.ClassContextSpecific || decodedTag_stateattributes.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_stateattributes), "stateAttributes", "decoding", false)
				}
				if decodedTag_stateattributes.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_stateattributes), "stateAttributes", "decoding", false)
				}
				_ = rawVal_stateattributes
				if offset < 0 || offset >
					len(content) || n_stateattributes < 0 || n_stateattributes > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_stateattributes, reconstructionErr_stateattributes := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_stateattributes])
				if reconstructionErr_stateattributes != nil {
					return qualifyBERError(reconstructionErr_stateattributes, "stateAttributes", "decoding", false)
				}
				var dec_stateattributes StateAttributes
				if unmErr := dec_stateattributes.UnmarshalBER(reconstructed_stateattributes, ber.ChildDecodeOptions(opts, "stateAttributes")...); unmErr != nil {
					return qualifyBERError(unmErr, "stateAttributes", "decoding", false)
				}
				v.StateAttributes = &dec_stateattributes
				if offset < 0 || offset >
					len(content) || n_stateattributes < 0 || n_stateattributes > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_stateattributes
			}
		}
	}
	// Decode talkerPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "talkerPriority", content[offset:])
				decodedTag_talkerpriority, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "talkerPriority", "decoding", false)
				}
				if decodedTag_talkerpriority.Class != tag.ClassContextSpecific || decodedTag_talkerpriority.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_talkerpriority), "talkerPriority", "decoding", false)
				}
				if decodedTag_talkerpriority.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_talkerpriority), "talkerPriority", "decoding", false)
				}
				decVal_talkerpriority, intErr := ber.DecodeEnumeratedValue(rawVal_talkerpriority)
				if intErr != nil {
					return qualifyBERError(intErr, "talkerPriority", "decoding", false)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				if offset < 0 || offset >
					len(content) || n_talkerpriority < 0 || n_talkerpriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_talkerpriority
				if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
					if constraintErr := checkDecodedValue(opts, sbdb8a8_4, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additionalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "additionalInfo", content[offset:])
				decodedTag_additionalinfo, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalInfo", "decoding", false)
				}
				if decodedTag_additionalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalinfo.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_additionalinfo), "additionalInfo", "decoding", false)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalinfo.Constructed, rawVal_additionalinfo, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "additionalInfo", "decoding", false)
				}
				bsBitLength_additionalinfo, bsLenErr_additionalinfo := ber.BitStringBitLength(len(bsBytes_additionalinfo), bsUnused_additionalinfo)
				if bsLenErr_additionalinfo != nil {
					return qualifyBERError(bsLenErr_additionalinfo, "additionalInfo", "decoding", false)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: bsBitLength_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				if offset < 0 || offset >
					len(content) || n_additionalinfo < 0 || n_additionalinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalinfo
				if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_4, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode emergencyModeResetCommandFlag
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "emergencyModeResetCommandFlag", content[offset:])
				decodedTag_emergencymoderesetcommandflag, n_emergencymoderesetcommandflag, rawVal_emergencymoderesetcommandflag, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "emergencyModeResetCommandFlag", "decoding", false)
				}
				if decodedTag_emergencymoderesetcommandflag.Class != tag.ClassContextSpecific || decodedTag_emergencymoderesetcommandflag.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_emergencymoderesetcommandflag), "emergencyModeResetCommandFlag", "decoding", false)
				}
				if decodedTag_emergencymoderesetcommandflag.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_emergencymoderesetcommandflag), "emergencyModeResetCommandFlag", "decoding", false)
				}
				if len(rawVal_emergencymoderesetcommandflag) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_emergencymoderesetcommandflag)), "emergencyModeResetCommandFlag", "decoding", false)
				}
				v.EmergencyModeResetCommandFlag = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_emergencymoderesetcommandflag < 0 || n_emergencymoderesetcommandflag >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_emergencymoderesetcommandflag
			}
		}
	}
	// Decode sm-RP-UI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				ber.MarkPreflightTarget(opts, "sm-RP-UI", content[offset:])
				decodedTag_smrpui, n_smrpui, rawVal_smrpui, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sm-RP-UI", "decoding", false)
				}
				if decodedTag_smrpui.Class != tag.ClassContextSpecific || decodedTag_smrpui.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_smrpui), "sm-RP-UI", "decoding", false)
				}
				decVal_smrpui, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_smrpui.Constructed, rawVal_smrpui, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "sm-RP-UI", "decoding", false)
				}
				tmp_smrpui := SignalInfo(decVal_smrpui)
				v.SmRPUI = &tmp_smrpui
				if offset < 0 || offset >
					len(content) || n_smrpui < 0 || n_smrpui > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smrpui
				if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_4, "51.5", "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode an-APDU
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "an-APDU", content[offset:])
				decodedTag_anapdu, n_anapdu, rawVal_anapdu, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "an-APDU", "decoding", false)
				}
				if decodedTag_anapdu.Class != tag.ClassContextSpecific || decodedTag_anapdu.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_anapdu), "an-APDU", "decoding", false)
				}
				if decodedTag_anapdu.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_anapdu), "an-APDU", "decoding", false)
				}
				_ = rawVal_anapdu
				if offset < 0 || offset >
					len(content) || n_anapdu < 0 || n_anapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_anapdu, reconstructionErr_anapdu := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_anapdu])
				if reconstructionErr_anapdu != nil {
					return qualifyBERError(reconstructionErr_anapdu, "an-APDU", "decoding", false)
				}
				var dec_anapdu AccessNetworkSignalInfo
				if unmErr := dec_anapdu.UnmarshalBER(reconstructed_anapdu, ber.ChildDecodeOptions(opts, "an-APDU")...); unmErr != nil {
					return qualifyBERError(unmErr, "an-APDU", "decoding", false)
				}
				v.AnAPDU = &dec_anapdu
				if offset < 0 || offset >
					len(content) || n_anapdu < 0 || n_anapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_anapdu
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardGroupCallSignallingArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ForwardGroupCallSignallingArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sbdb8a8_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ProcessGroupCallSignallingArg to BER format.
func (v *ProcessGroupCallSignallingArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ProcessGroupCallSignallingArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ProcessGroupCallSignallingArg).MarshalBER, (*ProcessGroupCallSignallingArg).marshalBER, 3)

}
func (v *ProcessGroupCallSignallingArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.UplinkRequest != nil {
		enc_uplinkrequest := ber.EncodeNull()
		retagged_enc_uplinkrequest, tagErr_enc_uplinkrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_uplinkrequest)
		if tagErr_enc_uplinkrequest != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkrequest, "uplinkRequest", "encoding", false)
		}
		enc_uplinkrequest = retagged_enc_uplinkrequest
		children = append(children, enc_uplinkrequest...)
	}
	if v.UplinkReleaseIndication != nil {
		enc_uplinkreleaseindication := ber.EncodeNull()
		retagged_enc_uplinkreleaseindication, tagErr_enc_uplinkreleaseindication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uplinkreleaseindication)
		if tagErr_enc_uplinkreleaseindication != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkreleaseindication, "uplinkReleaseIndication", "encoding", false)
		}
		enc_uplinkreleaseindication = retagged_enc_uplinkreleaseindication
		children = append(children, enc_uplinkreleaseindication...)
	}
	if v.ReleaseGroupCall != nil {
		enc_releasegroupcall := ber.EncodeNull()
		retagged_enc_releasegroupcall, tagErr_enc_releasegroupcall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_releasegroupcall)
		if tagErr_enc_releasegroupcall != nil {
			return nil, qualifyBERError(tagErr_enc_releasegroupcall, "releaseGroupCall", "encoding", false)
		}
		enc_releasegroupcall = retagged_enc_releasegroupcall
		children = append(children, enc_releasegroupcall...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := checkEncodedValue(opts, sbdb8a8_5, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, qualifyBERError(tagErr_enc_talkerpriority, "talkerPriority", "encoding", false)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalInfo", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_5, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, ber.UnusedBitCount(v.AdditionalInfo.BitLength))
		if encodeErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalinfo, "additionalInfo", "encoding", false)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalinfo, "additionalInfo", "encoding", false)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.EmergencyModeResetCommandFlag != nil {
		enc_emergencymoderesetcommandflag := ber.EncodeNull()
		retagged_enc_emergencymoderesetcommandflag, tagErr_enc_emergencymoderesetcommandflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_emergencymoderesetcommandflag)
		if tagErr_enc_emergencymoderesetcommandflag != nil {
			return nil, qualifyBERError(tagErr_enc_emergencymoderesetcommandflag, "emergencyModeResetCommandFlag", "encoding", false)
		}
		enc_emergencymoderesetcommandflag = retagged_enc_emergencymoderesetcommandflag
		children = append(children, enc_emergencymoderesetcommandflag...)
	}
	if v.AnAPDU != nil {
		enc_anapdu, err := v.AnAPDU.MarshalBER(ber.ChildEncodeOptions(opts, "an-APDU")...)
		if err != nil {
			return nil, qualifyBERError(err, "an-APDU", "encoding", false)
		}
		retagged_enc_anapdu, tagErr_enc_anapdu := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_anapdu)
		if tagErr_enc_anapdu != nil {
			return nil, qualifyBERError(tagErr_enc_anapdu, "an-APDU", "encoding", false)
		}
		enc_anapdu = retagged_enc_anapdu
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_anapdu)
		children = append(children, enc_anapdu...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sbdb8a8_5, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sbdb8a8_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ProcessGroupCallSignallingArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ProcessGroupCallSignallingArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ProcessGroupCallSignallingArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ProcessGroupCallSignallingArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.UplinkRequest != nil {
		enc_uplinkrequest := ber.EncodeNull()
		retagged_enc_uplinkrequest, tagErr_enc_uplinkrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_uplinkrequest)
		if tagErr_enc_uplinkrequest != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkrequest, "uplinkRequest", "encoding", true)
		}
		enc_uplinkrequest = retagged_enc_uplinkrequest
		children = append(children, enc_uplinkrequest...)
	}
	if v.UplinkReleaseIndication != nil {
		enc_uplinkreleaseindication := ber.EncodeNull()
		retagged_enc_uplinkreleaseindication, tagErr_enc_uplinkreleaseindication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uplinkreleaseindication)
		if tagErr_enc_uplinkreleaseindication != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkreleaseindication, "uplinkReleaseIndication", "encoding", true)
		}
		enc_uplinkreleaseindication = retagged_enc_uplinkreleaseindication
		children = append(children, enc_uplinkreleaseindication...)
	}
	if v.ReleaseGroupCall != nil {
		enc_releasegroupcall := ber.EncodeNull()
		retagged_enc_releasegroupcall, tagErr_enc_releasegroupcall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_releasegroupcall)
		if tagErr_enc_releasegroupcall != nil {
			return nil, qualifyBERError(tagErr_enc_releasegroupcall, "releaseGroupCall", "encoding", true)
		}
		enc_releasegroupcall = retagged_enc_releasegroupcall
		children = append(children, enc_releasegroupcall...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := checkEncodedValue(nil, sbdb8a8_5, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, qualifyBERError(tagErr_enc_talkerpriority, "talkerPriority", "encoding", true)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalInfo", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_5, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, ber.UnusedBitCount(v.AdditionalInfo.BitLength))
		if encodeErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalinfo, "additionalInfo", "encoding", true)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalinfo, "additionalInfo", "encoding", true)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.EmergencyModeResetCommandFlag != nil {
		enc_emergencymoderesetcommandflag := ber.EncodeNull()
		retagged_enc_emergencymoderesetcommandflag, tagErr_enc_emergencymoderesetcommandflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_emergencymoderesetcommandflag)
		if tagErr_enc_emergencymoderesetcommandflag != nil {
			return nil, qualifyBERError(tagErr_enc_emergencymoderesetcommandflag, "emergencyModeResetCommandFlag", "encoding", true)
		}
		enc_emergencymoderesetcommandflag = retagged_enc_emergencymoderesetcommandflag
		children = append(children, enc_emergencymoderesetcommandflag...)
	}
	if v.AnAPDU != nil {
		enc_anapdu, err := v.AnAPDU.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "an-APDU", "encoding", true)
		}
		retagged_enc_anapdu, tagErr_enc_anapdu := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_anapdu)
		if tagErr_enc_anapdu != nil {
			return nil, qualifyBERError(tagErr_enc_anapdu, "an-APDU", "encoding", true)
		}
		enc_anapdu = retagged_enc_anapdu
		children = append(children, enc_anapdu...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sbdb8a8_5, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sbdb8a8_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ProcessGroupCallSignallingArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ProcessGroupCallSignallingArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ProcessGroupCallSignallingArg from BER/DER format.
func (destination *ProcessGroupCallSignallingArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ProcessGroupCallSignallingArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ProcessGroupCallSignallingArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sbdb8a8_5, "child", (*ProcessGroupCallSignallingArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ProcessGroupCallSignallingArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ProcessGroupCallSignallingArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ProcessGroupCallSignallingArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProcessGroupCallSignallingArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode uplinkRequest
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "uplinkRequest", content[offset:])
				decodedTag_uplinkrequest, n_uplinkrequest, rawVal_uplinkrequest, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uplinkRequest", "decoding", false)
				}
				if decodedTag_uplinkrequest.Class != tag.ClassContextSpecific || decodedTag_uplinkrequest.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_uplinkrequest), "uplinkRequest", "decoding", false)
				}
				if decodedTag_uplinkrequest.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_uplinkrequest), "uplinkRequest", "decoding", false)
				}
				if len(rawVal_uplinkrequest) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkrequest)), "uplinkRequest", "decoding", false)
				}
				v.UplinkRequest = &struct{}{}
				if offset > len(content) || n_uplinkrequest < 0 || n_uplinkrequest > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uplinkrequest
			}
		}
	}
	// Decode uplinkReleaseIndication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "uplinkReleaseIndication", content[offset:])
				decodedTag_uplinkreleaseindication, n_uplinkreleaseindication, rawVal_uplinkreleaseindication, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uplinkReleaseIndication", "decoding", false)
				}
				if decodedTag_uplinkreleaseindication.Class != tag.ClassContextSpecific || decodedTag_uplinkreleaseindication.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_uplinkreleaseindication), "uplinkReleaseIndication", "decoding", false)
				}
				if decodedTag_uplinkreleaseindication.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_uplinkreleaseindication), "uplinkReleaseIndication", "decoding", false)
				}
				if len(rawVal_uplinkreleaseindication) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkreleaseindication)), "uplinkReleaseIndication", "decoding", false)
				}
				v.UplinkReleaseIndication = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_uplinkreleaseindication < 0 || n_uplinkreleaseindication >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uplinkreleaseindication
			}
		}
	}
	// Decode releaseGroupCall
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "releaseGroupCall", content[offset:])
				decodedTag_releasegroupcall, n_releasegroupcall, rawVal_releasegroupcall, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "releaseGroupCall", "decoding", false)
				}
				if decodedTag_releasegroupcall.Class != tag.ClassContextSpecific || decodedTag_releasegroupcall.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_releasegroupcall), "releaseGroupCall", "decoding", false)
				}
				if decodedTag_releasegroupcall.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_releasegroupcall), "releaseGroupCall", "decoding", false)
				}
				if len(rawVal_releasegroupcall) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_releasegroupcall)), "releaseGroupCall", "decoding", false)
				}
				v.ReleaseGroupCall = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_releasegroupcall < 0 || n_releasegroupcall > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_releasegroupcall
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
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extensioncontainer
			}
		}
	}
	// Decode talkerPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "talkerPriority", content[offset:])
				decodedTag_talkerpriority, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "talkerPriority", "decoding", false)
				}
				if decodedTag_talkerpriority.Class != tag.ClassContextSpecific || decodedTag_talkerpriority.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_talkerpriority), "talkerPriority", "decoding", false)
				}
				if decodedTag_talkerpriority.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_talkerpriority), "talkerPriority", "decoding", false)
				}
				decVal_talkerpriority, intErr := ber.DecodeEnumeratedValue(rawVal_talkerpriority)
				if intErr != nil {
					return qualifyBERError(intErr, "talkerPriority", "decoding", false)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				if offset < 0 || offset >
					len(content) || n_talkerpriority < 0 || n_talkerpriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_talkerpriority
				if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
					if constraintErr := checkDecodedValue(opts, sbdb8a8_5, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additionalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "additionalInfo", content[offset:])
				decodedTag_additionalinfo, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalInfo", "decoding", false)
				}
				if decodedTag_additionalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalinfo.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_additionalinfo), "additionalInfo", "decoding", false)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalinfo.Constructed, rawVal_additionalinfo, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "additionalInfo", "decoding", false)
				}
				bsBitLength_additionalinfo, bsLenErr_additionalinfo := ber.BitStringBitLength(len(bsBytes_additionalinfo), bsUnused_additionalinfo)
				if bsLenErr_additionalinfo != nil {
					return qualifyBERError(bsLenErr_additionalinfo, "additionalInfo", "decoding", false)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: bsBitLength_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				if offset < 0 || offset >
					len(content) || n_additionalinfo < 0 || n_additionalinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalinfo
				if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_5, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode emergencyModeResetCommandFlag
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "emergencyModeResetCommandFlag", content[offset:])
				decodedTag_emergencymoderesetcommandflag, n_emergencymoderesetcommandflag, rawVal_emergencymoderesetcommandflag, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "emergencyModeResetCommandFlag", "decoding", false)
				}
				if decodedTag_emergencymoderesetcommandflag.Class != tag.ClassContextSpecific || decodedTag_emergencymoderesetcommandflag.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_emergencymoderesetcommandflag), "emergencyModeResetCommandFlag", "decoding", false)
				}
				if decodedTag_emergencymoderesetcommandflag.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_emergencymoderesetcommandflag), "emergencyModeResetCommandFlag", "decoding", false)
				}
				if len(rawVal_emergencymoderesetcommandflag) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_emergencymoderesetcommandflag)), "emergencyModeResetCommandFlag", "decoding", false)
				}
				v.EmergencyModeResetCommandFlag = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_emergencymoderesetcommandflag < 0 || n_emergencymoderesetcommandflag >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_emergencymoderesetcommandflag
			}
		}
	}
	// Decode an-APDU
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "an-APDU", content[offset:])
				decodedTag_anapdu, n_anapdu, rawVal_anapdu, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "an-APDU", "decoding", false)
				}
				if decodedTag_anapdu.Class != tag.ClassContextSpecific || decodedTag_anapdu.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_anapdu), "an-APDU", "decoding", false)
				}
				if decodedTag_anapdu.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_anapdu), "an-APDU", "decoding", false)
				}
				_ = rawVal_anapdu
				if offset < 0 || offset >
					len(content) || n_anapdu < 0 || n_anapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_anapdu, reconstructionErr_anapdu := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_anapdu])
				if reconstructionErr_anapdu != nil {
					return qualifyBERError(reconstructionErr_anapdu, "an-APDU", "decoding", false)
				}
				var dec_anapdu AccessNetworkSignalInfo
				if unmErr := dec_anapdu.UnmarshalBER(reconstructed_anapdu, ber.ChildDecodeOptions(opts, "an-APDU")...); unmErr != nil {
					return qualifyBERError(unmErr, "an-APDU", "decoding", false)
				}
				v.AnAPDU = &dec_anapdu
				if offset < 0 || offset >
					len(content) || n_anapdu < 0 || n_anapdu > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_anapdu
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProcessGroupCallSignallingArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ProcessGroupCallSignallingArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sbdb8a8_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes StateAttributes to BER format.
func (v *StateAttributes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: StateAttributes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*StateAttributes).MarshalBER, (*StateAttributes).marshalBER, 3)

}
func (v *StateAttributes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.DownlinkAttached != nil {
		enc_downlinkattached := ber.EncodeNull()
		retagged_enc_downlinkattached, tagErr_enc_downlinkattached := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_downlinkattached)
		if tagErr_enc_downlinkattached != nil {
			return nil, qualifyBERError(tagErr_enc_downlinkattached, "downlinkAttached", "encoding", false)
		}
		enc_downlinkattached = retagged_enc_downlinkattached
		children = append(children, enc_downlinkattached...)
	}
	if v.UplinkAttached != nil {
		enc_uplinkattached := ber.EncodeNull()
		retagged_enc_uplinkattached, tagErr_enc_uplinkattached := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_uplinkattached)
		if tagErr_enc_uplinkattached != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkattached, "uplinkAttached", "encoding", false)
		}
		enc_uplinkattached = retagged_enc_uplinkattached
		children = append(children, enc_uplinkattached...)
	}
	if v.DualCommunication != nil {
		enc_dualcommunication := ber.EncodeNull()
		retagged_enc_dualcommunication, tagErr_enc_dualcommunication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_dualcommunication)
		if tagErr_enc_dualcommunication != nil {
			return nil, qualifyBERError(tagErr_enc_dualcommunication, "dualCommunication", "encoding", false)
		}
		enc_dualcommunication = retagged_enc_dualcommunication
		children = append(children, enc_dualcommunication...)
	}
	if v.CallOriginator != nil {
		enc_calloriginator := ber.EncodeNull()
		retagged_enc_calloriginator, tagErr_enc_calloriginator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_calloriginator)
		if tagErr_enc_calloriginator != nil {
			return nil, qualifyBERError(tagErr_enc_calloriginator, "callOriginator", "encoding", false)
		}
		enc_calloriginator = retagged_enc_calloriginator
		children = append(children, enc_calloriginator...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *StateAttributes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes StateAttributes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *StateAttributes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: StateAttributes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.DownlinkAttached != nil {
		enc_downlinkattached := ber.EncodeNull()
		retagged_enc_downlinkattached, tagErr_enc_downlinkattached := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_downlinkattached)
		if tagErr_enc_downlinkattached != nil {
			return nil, qualifyBERError(tagErr_enc_downlinkattached, "downlinkAttached", "encoding", true)
		}
		enc_downlinkattached = retagged_enc_downlinkattached
		children = append(children, enc_downlinkattached...)
	}
	if v.UplinkAttached != nil {
		enc_uplinkattached := ber.EncodeNull()
		retagged_enc_uplinkattached, tagErr_enc_uplinkattached := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_uplinkattached)
		if tagErr_enc_uplinkattached != nil {
			return nil, qualifyBERError(tagErr_enc_uplinkattached, "uplinkAttached", "encoding", true)
		}
		enc_uplinkattached = retagged_enc_uplinkattached
		children = append(children, enc_uplinkattached...)
	}
	if v.DualCommunication != nil {
		enc_dualcommunication := ber.EncodeNull()
		retagged_enc_dualcommunication, tagErr_enc_dualcommunication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_dualcommunication)
		if tagErr_enc_dualcommunication != nil {
			return nil, qualifyBERError(tagErr_enc_dualcommunication, "dualCommunication", "encoding", true)
		}
		enc_dualcommunication = retagged_enc_dualcommunication
		children = append(children, enc_dualcommunication...)
	}
	if v.CallOriginator != nil {
		enc_calloriginator := ber.EncodeNull()
		retagged_enc_calloriginator, tagErr_enc_calloriginator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_calloriginator)
		if tagErr_enc_calloriginator != nil {
			return nil, qualifyBERError(tagErr_enc_calloriginator, "callOriginator", "encoding", true)
		}
		enc_calloriginator = retagged_enc_calloriginator
		children = append(children, enc_calloriginator...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding StateAttributes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *StateAttributes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes StateAttributes from BER/DER format.
func (destination *StateAttributes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: StateAttributes destination is nil", ber.ErrInvalidValue)
	}
	v := new(StateAttributes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "MAP-GR-DataTypes.StateAttributes", "child", (*StateAttributes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = StateAttributes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*StateAttributes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding StateAttributes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "StateAttributes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode downlinkAttached
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "downlinkAttached", content[offset:])
				decodedTag_downlinkattached, n_downlinkattached, rawVal_downlinkattached, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "downlinkAttached", "decoding", false)
				}
				if decodedTag_downlinkattached.Class != tag.ClassContextSpecific || decodedTag_downlinkattached.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_downlinkattached), "downlinkAttached", "decoding", false)
				}
				if decodedTag_downlinkattached.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_downlinkattached), "downlinkAttached", "decoding", false)
				}
				if len(rawVal_downlinkattached) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_downlinkattached)), "downlinkAttached", "decoding", false)
				}
				v.DownlinkAttached = &struct{}{}
				if offset > len(content) || n_downlinkattached < 0 || n_downlinkattached > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_downlinkattached
			}
		}
	}
	// Decode uplinkAttached
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "uplinkAttached", content[offset:])
				decodedTag_uplinkattached, n_uplinkattached, rawVal_uplinkattached, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "uplinkAttached", "decoding", false)
				}
				if decodedTag_uplinkattached.Class != tag.ClassContextSpecific || decodedTag_uplinkattached.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_uplinkattached), "uplinkAttached", "decoding", false)
				}
				if decodedTag_uplinkattached.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_uplinkattached), "uplinkAttached", "decoding", false)
				}
				if len(rawVal_uplinkattached) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkattached)), "uplinkAttached", "decoding", false)
				}
				v.UplinkAttached = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_uplinkattached < 0 || n_uplinkattached >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_uplinkattached
			}
		}
	}
	// Decode dualCommunication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "dualCommunication", content[offset:])
				decodedTag_dualcommunication, n_dualcommunication, rawVal_dualcommunication, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "dualCommunication", "decoding", false)
				}
				if decodedTag_dualcommunication.Class != tag.ClassContextSpecific || decodedTag_dualcommunication.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_dualcommunication), "dualCommunication", "decoding", false)
				}
				if decodedTag_dualcommunication.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_dualcommunication), "dualCommunication", "decoding", false)
				}
				if len(rawVal_dualcommunication) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_dualcommunication)), "dualCommunication", "decoding", false)
				}
				v.DualCommunication = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_dualcommunication < 0 || n_dualcommunication >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_dualcommunication
			}
		}
	}
	// Decode callOriginator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "callOriginator", content[offset:])
				decodedTag_calloriginator, n_calloriginator, rawVal_calloriginator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callOriginator", "decoding", false)
				}
				if decodedTag_calloriginator.Class != tag.ClassContextSpecific || decodedTag_calloriginator.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_calloriginator), "callOriginator", "decoding", false)
				}
				if decodedTag_calloriginator.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_calloriginator), "callOriginator", "decoding", false)
				}
				if len(rawVal_calloriginator) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_calloriginator)), "callOriginator", "decoding", false)
				}
				v.CallOriginator = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_calloriginator < 0 || n_calloriginator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_calloriginator
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "StateAttributes", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SendGroupCallInfoArg to BER format.
func (v *SendGroupCallInfoArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallInfoArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendGroupCallInfoArg).MarshalBER, (*SendGroupCallInfoArg).marshalBER, 3)

}
func (v *SendGroupCallInfoArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_requestedinfo := ber.EncodeEnumerated(int64(v.RequestedInfo))
	children = append(children, enc_requestedinfo...)
	if len(v.GroupId) < 4 || len(v.GroupId) > 4 {
		if constraintErr := checkEncodedLength(opts, sbdb8a8_6, "51.5", "groupId", "SIZE (4)", len(v.GroupId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_groupid, encodeErr_enc_groupid := ber.EncodeOctetString([]byte(v.GroupId))
	if encodeErr_enc_groupid != nil {
		return nil, qualifyBERError(encodeErr_enc_groupid, "groupId", "encoding", false)
	}
	children = append(children, enc_groupid...)
	if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
		if constraintErr := checkEncodedLength(opts, sbdb8a8_6, "51.5", "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(v.Teleservice))
	if encodeErr_enc_teleservice != nil {
		return nil, qualifyBERError(encodeErr_enc_teleservice, "teleservice", "encoding", false)
	}
	children = append(children, enc_teleservice...)
	if v.CellId != nil {
		if len(*v.CellId) < 5 || len(*v.CellId) > 7 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_6, "51.5", "cellId", "SIZE (5..7)", len(*v.CellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cellid, encodeErr_enc_cellid := ber.EncodeOctetString([]byte(*v.CellId))
		if encodeErr_enc_cellid != nil {
			return nil, qualifyBERError(encodeErr_enc_cellid, "cellId", "encoding", false)
		}
		retagged_enc_cellid, tagErr_enc_cellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cellid)
		if tagErr_enc_cellid != nil {
			return nil, qualifyBERError(tagErr_enc_cellid, "cellId", "encoding", false)
		}
		enc_cellid = retagged_enc_cellid
		children = append(children, enc_cellid...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_6, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Tmsi != nil {
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_6, "51.5", "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tmsi, encodeErr_enc_tmsi := ber.EncodeOctetString([]byte(*v.Tmsi))
		if encodeErr_enc_tmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_tmsi, "tmsi", "encoding", false)
		}
		retagged_enc_tmsi, tagErr_enc_tmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tmsi)
		if tagErr_enc_tmsi != nil {
			return nil, qualifyBERError(tagErr_enc_tmsi, "tmsi", "encoding", false)
		}
		enc_tmsi = retagged_enc_tmsi
		children = append(children, enc_tmsi...)
	}
	if v.AdditionalInfo != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalInfo", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_6, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, ber.UnusedBitCount(v.AdditionalInfo.BitLength))
		if encodeErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalinfo, "additionalInfo", "encoding", false)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalinfo, "additionalInfo", "encoding", false)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := checkEncodedValue(opts, sbdb8a8_6, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, qualifyBERError(tagErr_enc_talkerpriority, "talkerPriority", "encoding", false)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.Cksn != nil {
		if len(*v.Cksn) < 1 || len(*v.Cksn) > 1 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_6, "51.5", "cksn", "SIZE (1)", len(*v.Cksn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cksn, encodeErr_enc_cksn := ber.EncodeOctetString([]byte(*v.Cksn))
		if encodeErr_enc_cksn != nil {
			return nil, qualifyBERError(encodeErr_enc_cksn, "cksn", "encoding", false)
		}
		retagged_enc_cksn, tagErr_enc_cksn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_cksn)
		if tagErr_enc_cksn != nil {
			return nil, qualifyBERError(tagErr_enc_cksn, "cksn", "encoding", false)
		}
		enc_cksn = retagged_enc_cksn
		children = append(children, enc_cksn...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sbdb8a8_6, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sbdb8a8_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendGroupCallInfoArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendGroupCallInfoArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendGroupCallInfoArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallInfoArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_requestedinfo := ber.EncodeEnumerated(int64(v.RequestedInfo))
	children = append(children, enc_requestedinfo...)
	if len(v.GroupId) < 4 || len(v.GroupId) > 4 {
		if constraintErr := checkEncodedLength(nil, sbdb8a8_6, "51.5", "groupId", "SIZE (4)", len(v.GroupId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_groupid, encodeErr_enc_groupid := ber.EncodeOctetString([]byte(v.GroupId))
	if encodeErr_enc_groupid != nil {
		return nil, qualifyBERError(encodeErr_enc_groupid, "groupId", "encoding", true)
	}
	children = append(children, enc_groupid...)
	if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
		if constraintErr := checkEncodedLength(nil, sbdb8a8_6, "51.5", "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(v.Teleservice))
	if encodeErr_enc_teleservice != nil {
		return nil, qualifyBERError(encodeErr_enc_teleservice, "teleservice", "encoding", true)
	}
	children = append(children, enc_teleservice...)
	if v.CellId != nil {
		if len(*v.CellId) < 5 || len(*v.CellId) > 7 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_6, "51.5", "cellId", "SIZE (5..7)", len(*v.CellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cellid, encodeErr_enc_cellid := ber.EncodeOctetString([]byte(*v.CellId))
		if encodeErr_enc_cellid != nil {
			return nil, qualifyBERError(encodeErr_enc_cellid, "cellId", "encoding", true)
		}
		retagged_enc_cellid, tagErr_enc_cellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cellid)
		if tagErr_enc_cellid != nil {
			return nil, qualifyBERError(tagErr_enc_cellid, "cellId", "encoding", true)
		}
		enc_cellid = retagged_enc_cellid
		children = append(children, enc_cellid...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_6, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Tmsi != nil {
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_6, "51.5", "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tmsi, encodeErr_enc_tmsi := ber.EncodeOctetString([]byte(*v.Tmsi))
		if encodeErr_enc_tmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_tmsi, "tmsi", "encoding", true)
		}
		retagged_enc_tmsi, tagErr_enc_tmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tmsi)
		if tagErr_enc_tmsi != nil {
			return nil, qualifyBERError(tagErr_enc_tmsi, "tmsi", "encoding", true)
		}
		enc_tmsi = retagged_enc_tmsi
		children = append(children, enc_tmsi...)
	}
	if v.AdditionalInfo != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalInfo", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_6, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, ber.UnusedBitCount(v.AdditionalInfo.BitLength))
		if encodeErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalinfo, "additionalInfo", "encoding", true)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalinfo, "additionalInfo", "encoding", true)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := checkEncodedValue(nil, sbdb8a8_6, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, qualifyBERError(tagErr_enc_talkerpriority, "talkerPriority", "encoding", true)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.Cksn != nil {
		if len(*v.Cksn) < 1 || len(*v.Cksn) > 1 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_6, "51.5", "cksn", "SIZE (1)", len(*v.Cksn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cksn, encodeErr_enc_cksn := ber.EncodeOctetString([]byte(*v.Cksn))
		if encodeErr_enc_cksn != nil {
			return nil, qualifyBERError(encodeErr_enc_cksn, "cksn", "encoding", true)
		}
		retagged_enc_cksn, tagErr_enc_cksn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_cksn)
		if tagErr_enc_cksn != nil {
			return nil, qualifyBERError(tagErr_enc_cksn, "cksn", "encoding", true)
		}
		enc_cksn = retagged_enc_cksn
		children = append(children, enc_cksn...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sbdb8a8_6, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sbdb8a8_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SendGroupCallInfoArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendGroupCallInfoArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendGroupCallInfoArg from BER/DER format.
func (destination *SendGroupCallInfoArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendGroupCallInfoArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendGroupCallInfoArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sbdb8a8_6, "child", (*SendGroupCallInfoArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendGroupCallInfoArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendGroupCallInfoArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendGroupCallInfoArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendGroupCallInfoArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode requestedInfo
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field requestedInfo", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "requestedInfo", content[offset:])
		val_requestedinfo, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "requestedInfo", "decoding", false)
		}
		v.RequestedInfo = GRRequestedInfo(val_requestedinfo)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	// Decode groupId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field groupId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "groupId", content[offset:])
		val_groupid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "groupId", "decoding", false)
		}
		v.GroupId = LongGroupId(val_groupid)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.GroupId) < 4 || len(v.GroupId) > 4 {
			if constraintErr := checkDecodedLength(opts, sbdb8a8_6, "51.5", "groupId", "SIZE (4)", len(v.GroupId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode teleservice
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field teleservice", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "teleservice", content[offset:])
		val_teleservice, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "teleservice", "decoding", false)
		}
		v.Teleservice = ExtTeleserviceCode(val_teleservice)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
			if constraintErr := checkDecodedLength(opts, sbdb8a8_6, "51.5", "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cellId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "cellId", content[offset:])
				decodedTag_cellid, n_cellid, rawVal_cellid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cellId", "decoding", false)
				}
				if decodedTag_cellid.Class != tag.ClassContextSpecific || decodedTag_cellid.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_cellid), "cellId", "decoding", false)
				}
				decVal_cellid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cellid.Constructed, rawVal_cellid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "cellId", "decoding", false)
				}
				tmp_cellid := GlobalCellId(decVal_cellid)
				v.CellId = &tmp_cellid
				if offset < 0 || offset >
					len(content) || n_cellid < 0 || n_cellid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cellid
				if len(*v.CellId) < 5 || len(*v.CellId) > 7 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_6, "51.5", "cellId", "SIZE (5..7)", len(*v.CellId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_6, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode tmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "tmsi", content[offset:])
				decodedTag_tmsi, n_tmsi, rawVal_tmsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "tmsi", "decoding", false)
				}
				if decodedTag_tmsi.Class != tag.ClassContextSpecific || decodedTag_tmsi.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tmsi), "tmsi", "decoding", false)
				}
				decVal_tmsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tmsi.Constructed, rawVal_tmsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "tmsi", "decoding", false)
				}
				tmp_tmsi := TMSI(decVal_tmsi)
				v.Tmsi = &tmp_tmsi
				if offset < 0 || offset >
					len(content) || n_tmsi < 0 || n_tmsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tmsi
				if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_6, "51.5", "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additionalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "additionalInfo", content[offset:])
				decodedTag_additionalinfo, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalInfo", "decoding", false)
				}
				if decodedTag_additionalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalinfo.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_additionalinfo), "additionalInfo", "decoding", false)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalinfo.Constructed, rawVal_additionalinfo, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "additionalInfo", "decoding", false)
				}
				bsBitLength_additionalinfo, bsLenErr_additionalinfo := ber.BitStringBitLength(len(bsBytes_additionalinfo), bsUnused_additionalinfo)
				if bsLenErr_additionalinfo != nil {
					return qualifyBERError(bsLenErr_additionalinfo, "additionalInfo", "decoding", false)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: bsBitLength_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				if offset < 0 || offset >
					len(content) || n_additionalinfo < 0 || n_additionalinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalinfo
				if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_6, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode talkerPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "talkerPriority", content[offset:])
				decodedTag_talkerpriority, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "talkerPriority", "decoding", false)
				}
				if decodedTag_talkerpriority.Class != tag.ClassContextSpecific || decodedTag_talkerpriority.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_talkerpriority), "talkerPriority", "decoding", false)
				}
				if decodedTag_talkerpriority.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_talkerpriority), "talkerPriority", "decoding", false)
				}
				decVal_talkerpriority, intErr := ber.DecodeEnumeratedValue(rawVal_talkerpriority)
				if intErr != nil {
					return qualifyBERError(intErr, "talkerPriority", "decoding", false)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				if offset < 0 || offset >
					len(content) || n_talkerpriority < 0 || n_talkerpriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_talkerpriority
				if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
					if constraintErr := checkDecodedValue(opts, sbdb8a8_6, "20", "talkerPriority", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.TalkerPriority))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cksn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "cksn", content[offset:])
				decodedTag_cksn, n_cksn, rawVal_cksn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cksn", "decoding", false)
				}
				if decodedTag_cksn.Class != tag.ClassContextSpecific || decodedTag_cksn.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_cksn), "cksn", "decoding", false)
				}
				decVal_cksn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cksn.Constructed, rawVal_cksn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "cksn", "decoding", false)
				}
				tmp_cksn := Cksn(decVal_cksn)
				v.Cksn = &tmp_cksn
				if offset < 0 || offset >
					len(content) || n_cksn < 0 || n_cksn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cksn
				if len(*v.Cksn) < 1 || len(*v.Cksn) > 1 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_6, "51.5", "cksn", "SIZE (1)", len(*v.Cksn)); constraintErr != nil {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallInfoArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallInfoArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sbdb8a8_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SendGroupCallInfoRes to BER format.
func (v *SendGroupCallInfoRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallInfoRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendGroupCallInfoRes).MarshalBER, (*SendGroupCallInfoRes).marshalBER, 3)

}
func (v *SendGroupCallInfoRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.AnchorMSCAddress != nil {
		if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 9 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_7, "51.5", "anchorMSC-Address", "SIZE (1..9)", len(*v.AnchorMSCAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 20 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_7, "51.5", "anchorMSC-Address", "SIZE (1..20)", len(*v.AnchorMSCAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_anchormscaddress, encodeErr_enc_anchormscaddress := ber.EncodeOctetString([]byte(*v.AnchorMSCAddress))
		if encodeErr_enc_anchormscaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_anchormscaddress, "anchorMSC-Address", "encoding", false)
		}
		retagged_enc_anchormscaddress, tagErr_enc_anchormscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_anchormscaddress)
		if tagErr_enc_anchormscaddress != nil {
			return nil, qualifyBERError(tagErr_enc_anchormscaddress, "anchorMSC-Address", "encoding", false)
		}
		enc_anchormscaddress = retagged_enc_anchormscaddress
		children = append(children, enc_anchormscaddress...)
	}
	if v.AsciCallReference != nil {
		if len(*v.AsciCallReference) < 1 || len(*v.AsciCallReference) > 8 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_7, "51.5", "asciCallReference", "SIZE (1..8)", len(*v.AsciCallReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ascicallreference, encodeErr_enc_ascicallreference := ber.EncodeOctetString([]byte(*v.AsciCallReference))
		if encodeErr_enc_ascicallreference != nil {
			return nil, qualifyBERError(encodeErr_enc_ascicallreference, "asciCallReference", "encoding", false)
		}
		retagged_enc_ascicallreference, tagErr_enc_ascicallreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ascicallreference)
		if tagErr_enc_ascicallreference != nil {
			return nil, qualifyBERError(tagErr_enc_ascicallreference, "asciCallReference", "encoding", false)
		}
		enc_ascicallreference = retagged_enc_ascicallreference
		children = append(children, enc_ascicallreference...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_7, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.AdditionalInfo != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalInfo", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_7, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, ber.UnusedBitCount(v.AdditionalInfo.BitLength))
		if encodeErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalinfo, "additionalInfo", "encoding", false)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalinfo, "additionalInfo", "encoding", false)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.AdditionalSubscriptions != nil {
		namedBits_AdditionalSubscriptions, namedBitErr_ := normalizeNamedBits(*v.AdditionalSubscriptions, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, opts, "additionalSubscriptions", sbdb8a8_7)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_AdditionalSubscriptions.Bytes, namedBits_AdditionalSubscriptions.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalSubscriptions", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if namedBits_AdditionalSubscriptions.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_AdditionalSubscriptions).BitLength < 3 || (namedBits_AdditionalSubscriptions).BitLength > 8 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_7, "51.5", "additionalSubscriptions", "SIZE (3..8)", namedBitObservedLength(namedBits_AdditionalSubscriptions)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalsubscriptions, encodeErr_enc_additionalsubscriptions := ber.EncodeBitString(namedBits_AdditionalSubscriptions.Bytes, ber.UnusedBitCount(namedBits_AdditionalSubscriptions.BitLength))
		if encodeErr_enc_additionalsubscriptions != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalsubscriptions, "additionalSubscriptions", "encoding", false)
		}
		retagged_enc_additionalsubscriptions, tagErr_enc_additionalsubscriptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalsubscriptions)
		if tagErr_enc_additionalsubscriptions != nil {
			return nil, qualifyBERError(tagErr_enc_additionalsubscriptions, "additionalSubscriptions", "encoding", false)
		}
		enc_additionalsubscriptions = retagged_enc_additionalsubscriptions
		children = append(children, enc_additionalsubscriptions...)
	}
	if v.Kc != nil {
		if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
			if constraintErr := checkEncodedLength(opts, sbdb8a8_7, "51.5", "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(*v.Kc))
		if encodeErr_enc_kc != nil {
			return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", false)
		}
		retagged_enc_kc, tagErr_enc_kc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_kc)
		if tagErr_enc_kc != nil {
			return nil, qualifyBERError(tagErr_enc_kc, "kc", "encoding", false)
		}
		enc_kc = retagged_enc_kc
		children = append(children, enc_kc...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, sbdb8a8_7, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, sbdb8a8_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendGroupCallInfoRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendGroupCallInfoRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendGroupCallInfoRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallInfoRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.AnchorMSCAddress != nil {
		if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 9 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_7, "51.5", "anchorMSC-Address", "SIZE (1..9)", len(*v.AnchorMSCAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 20 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_7, "51.5", "anchorMSC-Address", "SIZE (1..20)", len(*v.AnchorMSCAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_anchormscaddress, encodeErr_enc_anchormscaddress := ber.EncodeOctetString([]byte(*v.AnchorMSCAddress))
		if encodeErr_enc_anchormscaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_anchormscaddress, "anchorMSC-Address", "encoding", true)
		}
		retagged_enc_anchormscaddress, tagErr_enc_anchormscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_anchormscaddress)
		if tagErr_enc_anchormscaddress != nil {
			return nil, qualifyBERError(tagErr_enc_anchormscaddress, "anchorMSC-Address", "encoding", true)
		}
		enc_anchormscaddress = retagged_enc_anchormscaddress
		children = append(children, enc_anchormscaddress...)
	}
	if v.AsciCallReference != nil {
		if len(*v.AsciCallReference) < 1 || len(*v.AsciCallReference) > 8 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_7, "51.5", "asciCallReference", "SIZE (1..8)", len(*v.AsciCallReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ascicallreference, encodeErr_enc_ascicallreference := ber.EncodeOctetString([]byte(*v.AsciCallReference))
		if encodeErr_enc_ascicallreference != nil {
			return nil, qualifyBERError(encodeErr_enc_ascicallreference, "asciCallReference", "encoding", true)
		}
		retagged_enc_ascicallreference, tagErr_enc_ascicallreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ascicallreference)
		if tagErr_enc_ascicallreference != nil {
			return nil, qualifyBERError(tagErr_enc_ascicallreference, "asciCallReference", "encoding", true)
		}
		enc_ascicallreference = retagged_enc_ascicallreference
		children = append(children, enc_ascicallreference...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_7, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.AdditionalInfo != nil {
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalInfo", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_7, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, ber.UnusedBitCount(v.AdditionalInfo.BitLength))
		if encodeErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalinfo, "additionalInfo", "encoding", true)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_additionalinfo, "additionalInfo", "encoding", true)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.AdditionalSubscriptions != nil {
		namedBits_AdditionalSubscriptions, namedBitErr_ := normalizeNamedBits(*v.AdditionalSubscriptions, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, nil, "additionalSubscriptions", sbdb8a8_7)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_AdditionalSubscriptions.Bytes, namedBits_AdditionalSubscriptions.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "additionalSubscriptions", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:755
		if namedBits_AdditionalSubscriptions.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_AdditionalSubscriptions).BitLength < 3 || (namedBits_AdditionalSubscriptions).BitLength > 8 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_7, "51.5", "additionalSubscriptions", "SIZE (3..8)", namedBitObservedLength(namedBits_AdditionalSubscriptions)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_additionalsubscriptions, encodeErr_enc_additionalsubscriptions := ber.EncodeDERNamedBitString(namedBits_AdditionalSubscriptions.Bytes, namedBits_AdditionalSubscriptions.BitLength)
		if encodeErr_enc_additionalsubscriptions != nil {
			return nil, qualifyBERError(encodeErr_enc_additionalsubscriptions, "additionalSubscriptions", "encoding", true)
		}
		retagged_enc_additionalsubscriptions, tagErr_enc_additionalsubscriptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalsubscriptions)
		if tagErr_enc_additionalsubscriptions != nil {
			return nil, qualifyBERError(tagErr_enc_additionalsubscriptions, "additionalSubscriptions", "encoding", true)
		}
		enc_additionalsubscriptions = retagged_enc_additionalsubscriptions
		children = append(children, enc_additionalsubscriptions...)
	}
	if v.Kc != nil {
		if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
			if constraintErr := checkEncodedLength(nil, sbdb8a8_7, "51.5", "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(*v.Kc))
		if encodeErr_enc_kc != nil {
			return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", true)
		}
		retagged_enc_kc, tagErr_enc_kc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_kc)
		if tagErr_enc_kc != nil {
			return nil, qualifyBERError(tagErr_enc_kc, "kc", "encoding", true)
		}
		enc_kc = retagged_enc_kc
		children = append(children, enc_kc...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, sbdb8a8_7, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, sbdb8a8_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SendGroupCallInfoRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendGroupCallInfoRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendGroupCallInfoRes from BER/DER format.
func (destination *SendGroupCallInfoRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendGroupCallInfoRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendGroupCallInfoRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, sbdb8a8_7, "child", (*SendGroupCallInfoRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendGroupCallInfoRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendGroupCallInfoRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendGroupCallInfoRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendGroupCallInfoRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode anchorMSC-Address
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				ber.MarkPreflightTarget(opts, "anchorMSC-Address", content[offset:])
				decodedTag_anchormscaddress, n_anchormscaddress, rawVal_anchormscaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "anchorMSC-Address", "decoding", false)
				}
				if decodedTag_anchormscaddress.Class != tag.ClassContextSpecific || decodedTag_anchormscaddress.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_anchormscaddress), "anchorMSC-Address", "decoding", false)
				}
				decVal_anchormscaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_anchormscaddress.Constructed, rawVal_anchormscaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "anchorMSC-Address", "decoding", false)
				}
				tmp_anchormscaddress := ISDNAddressString(decVal_anchormscaddress)
				v.AnchorMSCAddress = &tmp_anchormscaddress
				if offset > len(content) || n_anchormscaddress < 0 || n_anchormscaddress > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_anchormscaddress
				if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 9 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_7, "51.5", "anchorMSC-Address", "SIZE (1..9)", len(*v.AnchorMSCAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 20 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_7, "51.5", "anchorMSC-Address", "SIZE (1..20)", len(*v.AnchorMSCAddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode asciCallReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "asciCallReference", content[offset:])
				decodedTag_ascicallreference, n_ascicallreference, rawVal_ascicallreference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "asciCallReference", "decoding", false)
				}
				if decodedTag_ascicallreference.Class != tag.ClassContextSpecific || decodedTag_ascicallreference.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_ascicallreference), "asciCallReference", "decoding", false)
				}
				decVal_ascicallreference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ascicallreference.Constructed, rawVal_ascicallreference, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "asciCallReference", "decoding", false)
				}
				tmp_ascicallreference := ASCICallReference(decVal_ascicallreference)
				v.AsciCallReference = &tmp_ascicallreference
				if offset < 0 || offset >
					len(content) || n_ascicallreference < 0 || n_ascicallreference >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ascicallreference
				if len(*v.AsciCallReference) < 1 || len(*v.AsciCallReference) > 8 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_7, "51.5", "asciCallReference", "SIZE (1..8)", len(*v.AsciCallReference)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "imsi", content[offset:])
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "imsi", "decoding", false)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_imsi), "imsi", "decoding", false)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "imsi", "decoding", false)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_7, "51.5", "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additionalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "additionalInfo", content[offset:])
				decodedTag_additionalinfo, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalInfo", "decoding", false)
				}
				if decodedTag_additionalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalinfo.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_additionalinfo), "additionalInfo", "decoding", false)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalinfo.Constructed, rawVal_additionalinfo, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "additionalInfo", "decoding", false)
				}
				bsBitLength_additionalinfo, bsLenErr_additionalinfo := ber.BitStringBitLength(len(bsBytes_additionalinfo), bsUnused_additionalinfo)
				if bsLenErr_additionalinfo != nil {
					return qualifyBERError(bsLenErr_additionalinfo, "additionalInfo", "decoding", false)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: bsBitLength_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				if offset < 0 || offset >
					len(content) || n_additionalinfo < 0 || n_additionalinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalinfo
				if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_7, "51.5", "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode additionalSubscriptions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "additionalSubscriptions", content[offset:])
				decodedTag_additionalsubscriptions, n_additionalsubscriptions, rawVal_additionalsubscriptions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "additionalSubscriptions", "decoding", false)
				}
				if decodedTag_additionalsubscriptions.Class != tag.ClassContextSpecific || decodedTag_additionalsubscriptions.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_additionalsubscriptions), "additionalSubscriptions", "decoding", false)
				}
				bsBytes_additionalsubscriptions, bsUnused_additionalsubscriptions, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalsubscriptions.Constructed, rawVal_additionalsubscriptions, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "additionalSubscriptions", "decoding", false)
				}
				bsBitLength_additionalsubscriptions, bsLenErr_additionalsubscriptions := ber.BitStringBitLength(len(bsBytes_additionalsubscriptions), bsUnused_additionalsubscriptions)
				if bsLenErr_additionalsubscriptions != nil {
					return qualifyBERError(bsLenErr_additionalsubscriptions, "additionalSubscriptions", "decoding", false)
				}
				tmp_additionalsubscriptions := runtime.BitString{Bytes: bsBytes_additionalsubscriptions, BitLength: bsBitLength_additionalsubscriptions}
				v.AdditionalSubscriptions = &tmp_additionalsubscriptions
				if offset < 0 || offset >
					len(content) || n_additionalsubscriptions < 0 || n_additionalsubscriptions >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalsubscriptions
				*v.AdditionalSubscriptions = ber.NormalizeNamedBitStringSize(*v.AdditionalSubscriptions, []ber.NamedBitSizeSet{{{Min: 3, Max: 8}}}, opts...)
				if (*v.AdditionalSubscriptions).BitLength < 3 || (*v.AdditionalSubscriptions).BitLength > 8 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_7, "51.5", "additionalSubscriptions", "SIZE (3..8)", (*v.AdditionalSubscriptions).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode kc
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "kc", content[offset:])
				decodedTag_kc, n_kc, rawVal_kc, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "kc", "decoding", false)
				}
				if decodedTag_kc.Class != tag.ClassContextSpecific || decodedTag_kc.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_kc), "kc", "decoding", false)
				}
				decVal_kc, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_kc.Constructed, rawVal_kc, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "kc", "decoding", false)
				}
				tmp_kc := Kc(decVal_kc)
				v.Kc = &tmp_kc
				if offset < 0 || offset >
					len(content) || n_kc < 0 || n_kc > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_kc
				if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
					if constraintErr := checkDecodedLength(opts, sbdb8a8_7, "51.5", "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallInfoRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallInfoRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, sbdb8a8_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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
	sbdb8a8_0 = "MAP-GR-DataTypes.PrepareGroupCallArg"
	sbdb8a8_1 = "MAP-GR-DataTypes.PrepareGroupCallRes"
	sbdb8a8_2 = "MAP-GR-DataTypes.SendGroupCallEndSignalArg"
	sbdb8a8_3 = "MAP-GR-DataTypes.SendGroupCallEndSignalRes"
	sbdb8a8_4 = "MAP-GR-DataTypes.ForwardGroupCallSignallingArg"
	sbdb8a8_5 = "MAP-GR-DataTypes.ProcessGroupCallSignallingArg"
	sbdb8a8_6 = "MAP-GR-DataTypes.SendGroupCallInfoArg"
	sbdb8a8_7 = "MAP-GR-DataTypes.SendGroupCallInfoRes"
)
