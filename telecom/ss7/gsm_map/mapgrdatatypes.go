// Code generated from ASN.1 module "MAP-GR-DataTypes". DO NOT EDIT.

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
	ExtData_               [][]byte            `asn1:"-" json:"-"`
	berOriginal_           []byte              `asn1:"-" json:"-"`
	berSnapshot_           []byte              `asn1:"-" json:"-"`
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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// SendGroupCallEndSignalArg represents the ASN.1 type SendGroupCallEndSignalArg (SEQUENCE).
type SendGroupCallEndSignalArg struct {
	Imsi               *IMSI               `asn1:",optional" json:"Imsi,omitempty"`
	ExtensionContainer *ExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	TalkerPriority     *TalkerPriority     `asn1:"tag:0,context,implicit,optional" json:"TalkerPriority,omitempty"`
	AdditionalInfo     *AdditionalInfo     `asn1:"tag:1,context,implicit,optional" json:"AdditionalInfo,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// TalkerPriority represents the ASN.1 ENUMERATED type TalkerPriority.
type TalkerPriority int64

const (
	TalkerPriorityNormal     TalkerPriority = 0
	TalkerPriorityPrivileged TalkerPriority = 1
	TalkerPriorityEmergency  TalkerPriority = 2
)

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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
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
	ExtData_                      [][]byte                 `asn1:"-" json:"-"`
	berOriginal_                  []byte                   `asn1:"-" json:"-"`
	berSnapshot_                  []byte                   `asn1:"-" json:"-"`
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
	ExtData_                      [][]byte                 `asn1:"-" json:"-"`
	berOriginal_                  []byte                   `asn1:"-" json:"-"`
	berSnapshot_                  []byte                   `asn1:"-" json:"-"`
}

// GroupKeyNumber represents the ASN.1 type GroupKeyNumber (INTEGER).
type GroupKeyNumber = int64

// CODECInfo represents the ASN.1 type CODEC-Info (OCTET_STRING).
type CODECInfo = []byte

// CipheringAlgorithm represents the ASN.1 type CipheringAlgorithm (OCTET_STRING).
type CipheringAlgorithm = []byte

// StateAttributes represents the ASN.1 type StateAttributes (SEQUENCE).
type StateAttributes struct {
	DownlinkAttached  *struct{} `asn1:"tag:5,context,implicit,optional" json:"DownlinkAttached,omitempty"`
	UplinkAttached    *struct{} `asn1:"tag:6,context,implicit,optional" json:"UplinkAttached,omitempty"`
	DualCommunication *struct{} `asn1:"tag:7,context,implicit,optional" json:"DualCommunication,omitempty"`
	CallOriginator    *struct{} `asn1:"tag:8,context,implicit,optional" json:"CallOriginator,omitempty"`
	berOriginal_      []byte    `asn1:"-" json:"-"`
	berSnapshot_      []byte    `asn1:"-" json:"-"`
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
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// GRRequestedInfo represents the ASN.1 ENUMERATED type RequestedInfo.
type GRRequestedInfo int64

const (
	GRRequestedInfoAnchorMSCAddressAndASCICallReference           GRRequestedInfo = 0
	GRRequestedInfoImsiAndAdditionalInfoAndAdditionalSubscription GRRequestedInfo = 1
)

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
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
	berOriginal_            []byte                   `asn1:"-" json:"-"`
	berSnapshot_            []byte                   `asn1:"-" json:"-"`
}

// MarshalBER encodes PrepareGroupCallArg to BER format.
func (v *PrepareGroupCallArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareGroupCallArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PrepareGroupCallArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
		if constraintErr := ber.CheckEncodedLength(opts, "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(v.Teleservice))
	if encodeErr_enc_teleservice != nil {
		return nil, fmt.Errorf("encoding teleservice: %w", encodeErr_enc_teleservice)
	}
	children = append(children, enc_teleservice...)
	if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ascicallreference, encodeErr_enc_ascicallreference := ber.EncodeOctetString([]byte(v.AsciCallReference))
	if encodeErr_enc_ascicallreference != nil {
		return nil, fmt.Errorf("encoding asciCallReference: %w", encodeErr_enc_ascicallreference)
	}
	children = append(children, enc_ascicallreference...)
	if len(v.CodecInfo) < 5 || len(v.CodecInfo) > 10 {
		if constraintErr := ber.CheckEncodedLength(opts, "codec-Info", "SIZE (5..10)", len(v.CodecInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_codecinfo, encodeErr_enc_codecinfo := ber.EncodeOctetString([]byte(v.CodecInfo))
	if encodeErr_enc_codecinfo != nil {
		return nil, fmt.Errorf("encoding codec-Info: %w", encodeErr_enc_codecinfo)
	}
	children = append(children, enc_codecinfo...)
	if len(v.CipheringAlgorithm) < 1 || len(v.CipheringAlgorithm) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "cipheringAlgorithm", "SIZE (1)", len(v.CipheringAlgorithm)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cipheringalgorithm, encodeErr_enc_cipheringalgorithm := ber.EncodeOctetString([]byte(v.CipheringAlgorithm))
	if encodeErr_enc_cipheringalgorithm != nil {
		return nil, fmt.Errorf("encoding cipheringAlgorithm: %w", encodeErr_enc_cipheringalgorithm)
	}
	children = append(children, enc_cipheringalgorithm...)
	if v.GroupKeyNumberVkId != nil {
		if !(int64(*v.GroupKeyNumberVkId) >= 0 && int64(*v.GroupKeyNumberVkId) <= 15) {
			if constraintErr := ber.CheckEncodedValue(opts, "groupKeyNumber-Vk-Id", "(0..15)", fmt.Sprint(int64(*v.GroupKeyNumberVkId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_groupkeynumbervkid := ber.EncodeInteger(int64(*v.GroupKeyNumberVkId))
		retagged_enc_groupkeynumbervkid, tagErr_enc_groupkeynumbervkid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_groupkeynumbervkid)
		if tagErr_enc_groupkeynumbervkid != nil {
			return nil, fmt.Errorf("encoding groupKeyNumber-Vk-Id: %w", tagErr_enc_groupkeynumbervkid)
		}
		enc_groupkeynumbervkid = retagged_enc_groupkeynumbervkid
		children = append(children, enc_groupkeynumbervkid...)
	}
	if v.GroupKey != nil {
		if len(*v.GroupKey) < 8 || len(*v.GroupKey) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "groupKey", "SIZE (8)", len(*v.GroupKey)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_groupkey, encodeErr_enc_groupkey := ber.EncodeOctetString([]byte(*v.GroupKey))
		if encodeErr_enc_groupkey != nil {
			return nil, fmt.Errorf("encoding groupKey: %w", encodeErr_enc_groupkey)
		}
		retagged_enc_groupkey, tagErr_enc_groupkey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_groupkey)
		if tagErr_enc_groupkey != nil {
			return nil, fmt.Errorf("encoding groupKey: %w", tagErr_enc_groupkey)
		}
		enc_groupkey = retagged_enc_groupkey
		children = append(children, enc_groupkey...)
	}
	if v.Priority != nil {
		if !(int64(*v.Priority) >= 0 && int64(*v.Priority) <= 15) {
			if constraintErr := ber.CheckEncodedValue(opts, "priority", "(0..15)", fmt.Sprint(int64(*v.Priority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_priority := ber.EncodeInteger(int64(*v.Priority))
		retagged_enc_priority, tagErr_enc_priority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_priority)
		if tagErr_enc_priority != nil {
			return nil, fmt.Errorf("encoding priority: %w", tagErr_enc_priority)
		}
		enc_priority = retagged_enc_priority
		children = append(children, enc_priority...)
	}
	if v.UplinkFree != nil {
		enc_uplinkfree := ber.EncodeNull()
		retagged_enc_uplinkfree, tagErr_enc_uplinkfree := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_uplinkfree)
		if tagErr_enc_uplinkfree != nil {
			return nil, fmt.Errorf("encoding uplinkFree: %w", tagErr_enc_uplinkfree)
		}
		enc_uplinkfree = retagged_enc_uplinkfree
		children = append(children, enc_uplinkfree...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.Vstk != nil {
		if len(*v.Vstk) < 16 || len(*v.Vstk) > 16 {
			if constraintErr := ber.CheckEncodedLength(opts, "vstk", "SIZE (16)", len(*v.Vstk)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vstk, encodeErr_enc_vstk := ber.EncodeOctetString([]byte(*v.Vstk))
		if encodeErr_enc_vstk != nil {
			return nil, fmt.Errorf("encoding vstk: %w", encodeErr_enc_vstk)
		}
		retagged_enc_vstk, tagErr_enc_vstk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_vstk)
		if tagErr_enc_vstk != nil {
			return nil, fmt.Errorf("encoding vstk: %w", tagErr_enc_vstk)
		}
		enc_vstk = retagged_enc_vstk
		children = append(children, enc_vstk...)
	}
	if v.VstkRand != nil {
		if len(*v.VstkRand) < 5 || len(*v.VstkRand) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "vstk-rand", "SIZE (5)", len(*v.VstkRand)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vstkrand, encodeErr_enc_vstkrand := ber.EncodeOctetString([]byte(*v.VstkRand))
		if encodeErr_enc_vstkrand != nil {
			return nil, fmt.Errorf("encoding vstk-rand: %w", encodeErr_enc_vstkrand)
		}
		retagged_enc_vstkrand, tagErr_enc_vstkrand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_vstkrand)
		if tagErr_enc_vstkrand != nil {
			return nil, fmt.Errorf("encoding vstk-rand: %w", tagErr_enc_vstkrand)
		}
		enc_vstkrand = retagged_enc_vstkrand
		children = append(children, enc_vstkrand...)
	}
	if v.TalkerChannelParameter != nil {
		enc_talkerchannelparameter := ber.EncodeNull()
		retagged_enc_talkerchannelparameter, tagErr_enc_talkerchannelparameter := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_talkerchannelparameter)
		if tagErr_enc_talkerchannelparameter != nil {
			return nil, fmt.Errorf("encoding talkerChannelParameter: %w", tagErr_enc_talkerchannelparameter)
		}
		enc_talkerchannelparameter = retagged_enc_talkerchannelparameter
		children = append(children, enc_talkerchannelparameter...)
	}
	if v.UplinkReplyIndicator != nil {
		enc_uplinkreplyindicator := ber.EncodeNull()
		retagged_enc_uplinkreplyindicator, tagErr_enc_uplinkreplyindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_uplinkreplyindicator)
		if tagErr_enc_uplinkreplyindicator != nil {
			return nil, fmt.Errorf("encoding uplinkReplyIndicator: %w", tagErr_enc_uplinkreplyindicator)
		}
		enc_uplinkreplyindicator = retagged_enc_uplinkreplyindicator
		children = append(children, enc_uplinkreplyindicator...)
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

// MarshalDER encodes PrepareGroupCallArg to DER format.
func (v *PrepareGroupCallArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareGroupCallArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
		if constraintErr := ber.CheckEncodedLength(nil, "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(v.Teleservice))
	if encodeErr_enc_teleservice != nil {
		return nil, fmt.Errorf("encoding teleservice: %w", encodeErr_enc_teleservice)
	}
	children = append(children, enc_teleservice...)
	if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ascicallreference, encodeErr_enc_ascicallreference := ber.EncodeOctetString([]byte(v.AsciCallReference))
	if encodeErr_enc_ascicallreference != nil {
		return nil, fmt.Errorf("encoding asciCallReference: %w", encodeErr_enc_ascicallreference)
	}
	children = append(children, enc_ascicallreference...)
	if len(v.CodecInfo) < 5 || len(v.CodecInfo) > 10 {
		if constraintErr := ber.CheckEncodedLength(nil, "codec-Info", "SIZE (5..10)", len(v.CodecInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_codecinfo, encodeErr_enc_codecinfo := ber.EncodeOctetString([]byte(v.CodecInfo))
	if encodeErr_enc_codecinfo != nil {
		return nil, fmt.Errorf("encoding codec-Info: %w", encodeErr_enc_codecinfo)
	}
	children = append(children, enc_codecinfo...)
	if len(v.CipheringAlgorithm) < 1 || len(v.CipheringAlgorithm) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "cipheringAlgorithm", "SIZE (1)", len(v.CipheringAlgorithm)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cipheringalgorithm, encodeErr_enc_cipheringalgorithm := ber.EncodeOctetString([]byte(v.CipheringAlgorithm))
	if encodeErr_enc_cipheringalgorithm != nil {
		return nil, fmt.Errorf("encoding cipheringAlgorithm: %w", encodeErr_enc_cipheringalgorithm)
	}
	children = append(children, enc_cipheringalgorithm...)
	if v.GroupKeyNumberVkId != nil {
		if !(int64(*v.GroupKeyNumberVkId) >= 0 && int64(*v.GroupKeyNumberVkId) <= 15) {
			if constraintErr := ber.CheckEncodedValue(nil, "groupKeyNumber-Vk-Id", "(0..15)", fmt.Sprint(int64(*v.GroupKeyNumberVkId))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_groupkeynumbervkid := ber.EncodeInteger(int64(*v.GroupKeyNumberVkId))
		retagged_enc_groupkeynumbervkid, tagErr_enc_groupkeynumbervkid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_groupkeynumbervkid)
		if tagErr_enc_groupkeynumbervkid != nil {
			return nil, fmt.Errorf("encoding groupKeyNumber-Vk-Id: %w", tagErr_enc_groupkeynumbervkid)
		}
		enc_groupkeynumbervkid = retagged_enc_groupkeynumbervkid
		children = append(children, enc_groupkeynumbervkid...)
	}
	if v.GroupKey != nil {
		if len(*v.GroupKey) < 8 || len(*v.GroupKey) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "groupKey", "SIZE (8)", len(*v.GroupKey)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_groupkey, encodeErr_enc_groupkey := ber.EncodeOctetString([]byte(*v.GroupKey))
		if encodeErr_enc_groupkey != nil {
			return nil, fmt.Errorf("encoding groupKey: %w", encodeErr_enc_groupkey)
		}
		retagged_enc_groupkey, tagErr_enc_groupkey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_groupkey)
		if tagErr_enc_groupkey != nil {
			return nil, fmt.Errorf("encoding groupKey: %w", tagErr_enc_groupkey)
		}
		enc_groupkey = retagged_enc_groupkey
		children = append(children, enc_groupkey...)
	}
	if v.Priority != nil {
		if !(int64(*v.Priority) >= 0 && int64(*v.Priority) <= 15) {
			if constraintErr := ber.CheckEncodedValue(nil, "priority", "(0..15)", fmt.Sprint(int64(*v.Priority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_priority := ber.EncodeInteger(int64(*v.Priority))
		retagged_enc_priority, tagErr_enc_priority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_priority)
		if tagErr_enc_priority != nil {
			return nil, fmt.Errorf("encoding priority: %w", tagErr_enc_priority)
		}
		enc_priority = retagged_enc_priority
		children = append(children, enc_priority...)
	}
	if v.UplinkFree != nil {
		enc_uplinkfree := ber.EncodeNull()
		retagged_enc_uplinkfree, tagErr_enc_uplinkfree := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_uplinkfree)
		if tagErr_enc_uplinkfree != nil {
			return nil, fmt.Errorf("encoding uplinkFree: %w", tagErr_enc_uplinkfree)
		}
		enc_uplinkfree = retagged_enc_uplinkfree
		children = append(children, enc_uplinkfree...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.Vstk != nil {
		if len(*v.Vstk) < 16 || len(*v.Vstk) > 16 {
			if constraintErr := ber.CheckEncodedLength(nil, "vstk", "SIZE (16)", len(*v.Vstk)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vstk, encodeErr_enc_vstk := ber.EncodeOctetString([]byte(*v.Vstk))
		if encodeErr_enc_vstk != nil {
			return nil, fmt.Errorf("encoding vstk: %w", encodeErr_enc_vstk)
		}
		retagged_enc_vstk, tagErr_enc_vstk := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_vstk)
		if tagErr_enc_vstk != nil {
			return nil, fmt.Errorf("encoding vstk: %w", tagErr_enc_vstk)
		}
		enc_vstk = retagged_enc_vstk
		children = append(children, enc_vstk...)
	}
	if v.VstkRand != nil {
		if len(*v.VstkRand) < 5 || len(*v.VstkRand) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, "vstk-rand", "SIZE (5)", len(*v.VstkRand)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_vstkrand, encodeErr_enc_vstkrand := ber.EncodeOctetString([]byte(*v.VstkRand))
		if encodeErr_enc_vstkrand != nil {
			return nil, fmt.Errorf("encoding vstk-rand: %w", encodeErr_enc_vstkrand)
		}
		retagged_enc_vstkrand, tagErr_enc_vstkrand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_vstkrand)
		if tagErr_enc_vstkrand != nil {
			return nil, fmt.Errorf("encoding vstk-rand: %w", tagErr_enc_vstkrand)
		}
		enc_vstkrand = retagged_enc_vstkrand
		children = append(children, enc_vstkrand...)
	}
	if v.TalkerChannelParameter != nil {
		enc_talkerchannelparameter := ber.EncodeNull()
		retagged_enc_talkerchannelparameter, tagErr_enc_talkerchannelparameter := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_talkerchannelparameter)
		if tagErr_enc_talkerchannelparameter != nil {
			return nil, fmt.Errorf("encoding talkerChannelParameter: %w", tagErr_enc_talkerchannelparameter)
		}
		enc_talkerchannelparameter = retagged_enc_talkerchannelparameter
		children = append(children, enc_talkerchannelparameter...)
	}
	if v.UplinkReplyIndicator != nil {
		enc_uplinkreplyindicator := ber.EncodeNull()
		retagged_enc_uplinkreplyindicator, tagErr_enc_uplinkreplyindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_uplinkreplyindicator)
		if tagErr_enc_uplinkreplyindicator != nil {
			return nil, fmt.Errorf("encoding uplinkReplyIndicator: %w", tagErr_enc_uplinkreplyindicator)
		}
		enc_uplinkreplyindicator = retagged_enc_uplinkreplyindicator
		children = append(children, enc_uplinkreplyindicator...)
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
		return nil, fmt.Errorf("encoding PrepareGroupCallArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrepareGroupCallArg from BER/DER format.
func (v *PrepareGroupCallArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PrepareGroupCallArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PrepareGroupCallArg{}
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
		return fmt.Errorf("decoding PrepareGroupCallArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareGroupCallArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode teleservice
	if offset >= len(content) {
		return fmt.Errorf("missing required field teleservice")
	}
	val_teleservice, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding teleservice: %w", err)
	}
	v.Teleservice = ExtTeleserviceCode(val_teleservice)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
		if constraintErr := ber.CheckDecodedLength(opts, "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode asciCallReference
	if offset >= len(content) {
		return fmt.Errorf("missing required field asciCallReference")
	}
	val_ascicallreference, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding asciCallReference: %w", err)
	}
	v.AsciCallReference = ASCICallReference(val_ascicallreference)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.AsciCallReference) < 1 || len(v.AsciCallReference) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "asciCallReference", "SIZE (1..8)", len(v.AsciCallReference)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode codec-Info
	if offset >= len(content) {
		return fmt.Errorf("missing required field codec-Info")
	}
	val_codecinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding codec-Info: %w", err)
	}
	v.CodecInfo = CODECInfo(val_codecinfo)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.CodecInfo) < 5 || len(v.CodecInfo) > 10 {
		if constraintErr := ber.CheckDecodedLength(opts, "codec-Info", "SIZE (5..10)", len(v.CodecInfo)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode cipheringAlgorithm
	if offset >= len(content) {
		return fmt.Errorf("missing required field cipheringAlgorithm")
	}
	val_cipheringalgorithm, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding cipheringAlgorithm: %w", err)
	}
	v.CipheringAlgorithm = CipheringAlgorithm(val_cipheringalgorithm)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.CipheringAlgorithm) < 1 || len(v.CipheringAlgorithm) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "cipheringAlgorithm", "SIZE (1)", len(v.CipheringAlgorithm)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode groupKeyNumber-Vk-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_groupkeynumbervkid, n_groupkeynumbervkid, rawVal_groupkeynumbervkid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding groupKeyNumber-Vk-Id: %w", err)
				}
				if decodedTag_groupkeynumbervkid.Class != tag.ClassContextSpecific || decodedTag_groupkeynumbervkid.Number != 0 || decodedTag_groupkeynumbervkid.Constructed != false {
					return fmt.Errorf("decoding groupKeyNumber-Vk-Id: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_groupkeynumbervkid)
				}
				decVal_groupkeynumbervkid, intErr := ber.DecodeIntegerValue(rawVal_groupkeynumbervkid)
				if intErr != nil {
					return fmt.Errorf("decoding groupKeyNumber-Vk-Id: %w", intErr)
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
					if constraintErr := ber.CheckDecodedValue(opts, "groupKeyNumber-Vk-Id", "(0..15)", fmt.Sprint(int64(*v.GroupKeyNumberVkId))); constraintErr != nil {
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
				decodedTag_groupkey, n_groupkey, rawVal_groupkey, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding groupKey: %w", err)
				}
				if decodedTag_groupkey.Class != tag.ClassContextSpecific || decodedTag_groupkey.Number != 1 {
					return fmt.Errorf("decoding groupKey: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_groupkey)
				}
				decVal_groupkey, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_groupkey.Constructed, rawVal_groupkey, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding groupKey: %w", octetErr)
				}
				tmp_groupkey := Kc(decVal_groupkey)
				v.GroupKey = &tmp_groupkey
				if offset < 0 || offset >
					len(content) || n_groupkey < 0 || n_groupkey > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_groupkey
				if len(*v.GroupKey) < 8 || len(*v.GroupKey) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "groupKey", "SIZE (8)", len(*v.GroupKey)); constraintErr != nil {
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
				decodedTag_priority, n_priority, rawVal_priority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding priority: %w", err)
				}
				if decodedTag_priority.Class != tag.ClassContextSpecific || decodedTag_priority.Number != 2 || decodedTag_priority.Constructed != false {
					return fmt.Errorf("decoding priority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_priority)
				}
				decVal_priority, intErr := ber.DecodeIntegerValue(rawVal_priority)
				if intErr != nil {
					return fmt.Errorf("decoding priority: %w", intErr)
				}
				tmp_priority := EMLPPPriority(decVal_priority)
				v.Priority = &tmp_priority
				if offset < 0 || offset >
					len(content) || n_priority < 0 || n_priority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_priority
				if !(int64(*v.Priority) >= 0 && int64(*v.Priority) <= 15) {
					if constraintErr := ber.CheckDecodedValue(opts, "priority", "(0..15)", fmt.Sprint(int64(*v.Priority))); constraintErr != nil {
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
				decodedTag_uplinkfree, n_uplinkfree, rawVal_uplinkfree, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uplinkFree: %w", err)
				}
				if decodedTag_uplinkfree.Class != tag.ClassContextSpecific || decodedTag_uplinkfree.Number != 3 || decodedTag_uplinkfree.Constructed != false {
					return fmt.Errorf("decoding uplinkFree: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uplinkfree)
				}
				if len(rawVal_uplinkfree) != 0 {
					return fmt.Errorf("decoding uplinkFree: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkfree))
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
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
				decodedTag_vstk, n_vstk, rawVal_vstk, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding vstk: %w", err)
				}
				if decodedTag_vstk.Class != tag.ClassContextSpecific || decodedTag_vstk.Number != 5 {
					return fmt.Errorf("decoding vstk: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_vstk)
				}
				decVal_vstk, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_vstk.Constructed, rawVal_vstk, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding vstk: %w", octetErr)
				}
				tmp_vstk := VSTK(decVal_vstk)
				v.Vstk = &tmp_vstk
				if offset < 0 || offset >
					len(content) || n_vstk < 0 || n_vstk > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_vstk
				if len(*v.Vstk) < 16 || len(*v.Vstk) > 16 {
					if constraintErr := ber.CheckDecodedLength(opts, "vstk", "SIZE (16)", len(*v.Vstk)); constraintErr != nil {
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
				decodedTag_vstkrand, n_vstkrand, rawVal_vstkrand, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding vstk-rand: %w", err)
				}
				if decodedTag_vstkrand.Class != tag.ClassContextSpecific || decodedTag_vstkrand.Number != 6 {
					return fmt.Errorf("decoding vstk-rand: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_vstkrand)
				}
				decVal_vstkrand, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_vstkrand.Constructed, rawVal_vstkrand, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding vstk-rand: %w", octetErr)
				}
				tmp_vstkrand := VSTKRAND(decVal_vstkrand)
				v.VstkRand = &tmp_vstkrand
				if offset < 0 || offset >
					len(content) || n_vstkrand < 0 || n_vstkrand > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_vstkrand
				if len(*v.VstkRand) < 5 || len(*v.VstkRand) > 5 {
					if constraintErr := ber.CheckDecodedLength(opts, "vstk-rand", "SIZE (5)", len(*v.VstkRand)); constraintErr != nil {
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
				decodedTag_talkerchannelparameter, n_talkerchannelparameter, rawVal_talkerchannelparameter, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding talkerChannelParameter: %w", err)
				}
				if decodedTag_talkerchannelparameter.Class != tag.ClassContextSpecific || decodedTag_talkerchannelparameter.Number != 7 || decodedTag_talkerchannelparameter.Constructed != false {
					return fmt.Errorf("decoding talkerChannelParameter: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_talkerchannelparameter)
				}
				if len(rawVal_talkerchannelparameter) != 0 {
					return fmt.Errorf("decoding talkerChannelParameter: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_talkerchannelparameter))
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
				decodedTag_uplinkreplyindicator, n_uplinkreplyindicator, rawVal_uplinkreplyindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uplinkReplyIndicator: %w", err)
				}
				if decodedTag_uplinkreplyindicator.Class != tag.ClassContextSpecific || decodedTag_uplinkreplyindicator.Number != 8 || decodedTag_uplinkreplyindicator.Constructed != false {
					return fmt.Errorf("decoding uplinkReplyIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uplinkreplyindicator)
				}
				if len(rawVal_uplinkreplyindicator) != 0 {
					return fmt.Errorf("decoding uplinkReplyIndicator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkreplyindicator))
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareGroupCallArg", Cause: extErr_}
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
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareGroupCallRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PrepareGroupCallRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "groupCallNumber", "SIZE (1..9)", len(v.GroupCallNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "groupCallNumber", "SIZE (1..20)", len(v.GroupCallNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_groupcallnumber, encodeErr_enc_groupcallnumber := ber.EncodeOctetString([]byte(v.GroupCallNumber))
	if encodeErr_enc_groupcallnumber != nil {
		return nil, fmt.Errorf("encoding groupCallNumber: %w", encodeErr_enc_groupcallnumber)
	}
	children = append(children, enc_groupcallnumber...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
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

// MarshalDER encodes PrepareGroupCallRes to DER format.
func (v *PrepareGroupCallRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrepareGroupCallRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "groupCallNumber", "SIZE (1..9)", len(v.GroupCallNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "groupCallNumber", "SIZE (1..20)", len(v.GroupCallNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_groupcallnumber, encodeErr_enc_groupcallnumber := ber.EncodeOctetString([]byte(v.GroupCallNumber))
	if encodeErr_enc_groupcallnumber != nil {
		return nil, fmt.Errorf("encoding groupCallNumber: %w", encodeErr_enc_groupcallnumber)
	}
	children = append(children, enc_groupcallnumber...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
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
		return nil, fmt.Errorf("encoding PrepareGroupCallRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrepareGroupCallRes from BER/DER format.
func (v *PrepareGroupCallRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PrepareGroupCallRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PrepareGroupCallRes{}
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
		return fmt.Errorf("decoding PrepareGroupCallRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrepareGroupCallRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode groupCallNumber
	if offset >= len(content) {
		return fmt.Errorf("missing required field groupCallNumber")
	}
	val_groupcallnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding groupCallNumber: %w", err)
	}
	v.GroupCallNumber = ISDNAddressString(val_groupcallnumber)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "groupCallNumber", "SIZE (1..9)", len(v.GroupCallNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.GroupCallNumber) < 1 || len(v.GroupCallNumber) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "groupCallNumber", "SIZE (1..20)", len(v.GroupCallNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareGroupCallRes", Cause: extErr_}
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
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallEndSignalArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SendGroupCallEndSignalArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		children = append(children, enc_imsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := ber.CheckEncodedValue(opts, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, fmt.Errorf("encoding talkerPriority: %w", tagErr_enc_talkerpriority)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := ber.CheckEncodedLength(opts, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		if encodeErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", encodeErr_enc_additionalinfo)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", tagErr_enc_additionalinfo)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
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

// MarshalDER encodes SendGroupCallEndSignalArg to DER format.
func (v *SendGroupCallEndSignalArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallEndSignalArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		children = append(children, enc_imsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := ber.CheckEncodedValue(nil, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, fmt.Errorf("encoding talkerPriority: %w", tagErr_enc_talkerpriority)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := ber.CheckEncodedLength(nil, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		if encodeErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", encodeErr_enc_additionalinfo)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", tagErr_enc_additionalinfo)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
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
		return nil, fmt.Errorf("encoding SendGroupCallEndSignalArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SendGroupCallEndSignalArg from BER/DER format.
func (v *SendGroupCallEndSignalArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SendGroupCallEndSignalArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SendGroupCallEndSignalArg{}
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
		return fmt.Errorf("decoding SendGroupCallEndSignalArg SEQUENCE: %w", err)
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
				val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI(val_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
				decodedTag_talkerpriority, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding talkerPriority: %w", err)
				}
				if decodedTag_talkerpriority.Class != tag.ClassContextSpecific || decodedTag_talkerpriority.Number != 0 || decodedTag_talkerpriority.Constructed != false {
					return fmt.Errorf("decoding talkerPriority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_talkerpriority)
				}
				decVal_talkerpriority, intErr := ber.DecodeEnumeratedValue(rawVal_talkerpriority)
				if intErr != nil {
					return fmt.Errorf("decoding talkerPriority: %w", intErr)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				if offset < 0 || offset >
					len(content) || n_talkerpriority < 0 || n_talkerpriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_talkerpriority
				if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
					if constraintErr := ber.CheckDecodedValue(opts, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
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
				decodedTag_additionalinfo, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding additionalInfo: %w", err)
				}
				if decodedTag_additionalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalinfo.Number != 1 {
					return fmt.Errorf("decoding additionalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalinfo)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalinfo.Constructed, rawVal_additionalinfo, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsErr)
				}
				bsBitLength_additionalinfo, bsLenErr_additionalinfo := ber.BitStringBitLength(len(bsBytes_additionalinfo), bsUnused_additionalinfo)
				if bsLenErr_additionalinfo != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsLenErr_additionalinfo)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: bsBitLength_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				if offset < 0 || offset >
					len(content) || n_additionalinfo < 0 || n_additionalinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalinfo
				if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
					if constraintErr := ber.CheckDecodedLength(opts, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallEndSignalArg", Cause: extErr_}
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
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallEndSignalRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SendGroupCallEndSignalRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
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

// MarshalDER encodes SendGroupCallEndSignalRes to DER format.
func (v *SendGroupCallEndSignalRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallEndSignalRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
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
		return nil, fmt.Errorf("encoding SendGroupCallEndSignalRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SendGroupCallEndSignalRes from BER/DER format.
func (v *SendGroupCallEndSignalRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SendGroupCallEndSignalRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SendGroupCallEndSignalRes{}
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
		return fmt.Errorf("decoding SendGroupCallEndSignalRes SEQUENCE: %w", err)
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallEndSignalRes", Cause: extErr_}
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
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardGroupCallSignallingArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ForwardGroupCallSignallingArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		children = append(children, enc_imsi...)
	}
	if v.UplinkRequestAck != nil {
		enc_uplinkrequestack := ber.EncodeNull()
		retagged_enc_uplinkrequestack, tagErr_enc_uplinkrequestack := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_uplinkrequestack)
		if tagErr_enc_uplinkrequestack != nil {
			return nil, fmt.Errorf("encoding uplinkRequestAck: %w", tagErr_enc_uplinkrequestack)
		}
		enc_uplinkrequestack = retagged_enc_uplinkrequestack
		children = append(children, enc_uplinkrequestack...)
	}
	if v.UplinkReleaseIndication != nil {
		enc_uplinkreleaseindication := ber.EncodeNull()
		retagged_enc_uplinkreleaseindication, tagErr_enc_uplinkreleaseindication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uplinkreleaseindication)
		if tagErr_enc_uplinkreleaseindication != nil {
			return nil, fmt.Errorf("encoding uplinkReleaseIndication: %w", tagErr_enc_uplinkreleaseindication)
		}
		enc_uplinkreleaseindication = retagged_enc_uplinkreleaseindication
		children = append(children, enc_uplinkreleaseindication...)
	}
	if v.UplinkRejectCommand != nil {
		enc_uplinkrejectcommand := ber.EncodeNull()
		retagged_enc_uplinkrejectcommand, tagErr_enc_uplinkrejectcommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_uplinkrejectcommand)
		if tagErr_enc_uplinkrejectcommand != nil {
			return nil, fmt.Errorf("encoding uplinkRejectCommand: %w", tagErr_enc_uplinkrejectcommand)
		}
		enc_uplinkrejectcommand = retagged_enc_uplinkrejectcommand
		children = append(children, enc_uplinkrejectcommand...)
	}
	if v.UplinkSeizedCommand != nil {
		enc_uplinkseizedcommand := ber.EncodeNull()
		retagged_enc_uplinkseizedcommand, tagErr_enc_uplinkseizedcommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_uplinkseizedcommand)
		if tagErr_enc_uplinkseizedcommand != nil {
			return nil, fmt.Errorf("encoding uplinkSeizedCommand: %w", tagErr_enc_uplinkseizedcommand)
		}
		enc_uplinkseizedcommand = retagged_enc_uplinkseizedcommand
		children = append(children, enc_uplinkseizedcommand...)
	}
	if v.UplinkReleaseCommand != nil {
		enc_uplinkreleasecommand := ber.EncodeNull()
		retagged_enc_uplinkreleasecommand, tagErr_enc_uplinkreleasecommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_uplinkreleasecommand)
		if tagErr_enc_uplinkreleasecommand != nil {
			return nil, fmt.Errorf("encoding uplinkReleaseCommand: %w", tagErr_enc_uplinkreleasecommand)
		}
		enc_uplinkreleasecommand = retagged_enc_uplinkreleasecommand
		children = append(children, enc_uplinkreleasecommand...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.StateAttributes != nil {
		enc_stateattributes, err := v.StateAttributes.MarshalBER(ber.ChildEncodeOptions(opts, "stateAttributes")...)
		if err != nil {
			return nil, fmt.Errorf("encoding stateAttributes: %w", err)
		}
		retagged_enc_stateattributes, tagErr_enc_stateattributes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_stateattributes)
		if tagErr_enc_stateattributes != nil {
			return nil, fmt.Errorf("encoding stateAttributes: %w", tagErr_enc_stateattributes)
		}
		enc_stateattributes = retagged_enc_stateattributes
		children = append(children, enc_stateattributes...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := ber.CheckEncodedValue(opts, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, fmt.Errorf("encoding talkerPriority: %w", tagErr_enc_talkerpriority)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := ber.CheckEncodedLength(opts, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		if encodeErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", encodeErr_enc_additionalinfo)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", tagErr_enc_additionalinfo)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.EmergencyModeResetCommandFlag != nil {
		enc_emergencymoderesetcommandflag := ber.EncodeNull()
		retagged_enc_emergencymoderesetcommandflag, tagErr_enc_emergencymoderesetcommandflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_emergencymoderesetcommandflag)
		if tagErr_enc_emergencymoderesetcommandflag != nil {
			return nil, fmt.Errorf("encoding emergencyModeResetCommandFlag: %w", tagErr_enc_emergencymoderesetcommandflag)
		}
		enc_emergencymoderesetcommandflag = retagged_enc_emergencymoderesetcommandflag
		children = append(children, enc_emergencymoderesetcommandflag...)
	}
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := ber.CheckEncodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		if encodeErr_enc_smrpui != nil {
			return nil, fmt.Errorf("encoding sm-RP-UI: %w", encodeErr_enc_smrpui)
		}
		retagged_enc_smrpui, tagErr_enc_smrpui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_smrpui)
		if tagErr_enc_smrpui != nil {
			return nil, fmt.Errorf("encoding sm-RP-UI: %w", tagErr_enc_smrpui)
		}
		enc_smrpui = retagged_enc_smrpui
		children = append(children, enc_smrpui...)
	}
	if v.AnAPDU != nil {
		enc_anapdu, err := v.AnAPDU.MarshalBER(ber.ChildEncodeOptions(opts, "an-APDU")...)
		if err != nil {
			return nil, fmt.Errorf("encoding an-APDU: %w", err)
		}
		retagged_enc_anapdu, tagErr_enc_anapdu := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_anapdu)
		if tagErr_enc_anapdu != nil {
			return nil, fmt.Errorf("encoding an-APDU: %w", tagErr_enc_anapdu)
		}
		enc_anapdu = retagged_enc_anapdu
		children = append(children, enc_anapdu...)
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

// MarshalDER encodes ForwardGroupCallSignallingArg to DER format.
func (v *ForwardGroupCallSignallingArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardGroupCallSignallingArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		children = append(children, enc_imsi...)
	}
	if v.UplinkRequestAck != nil {
		enc_uplinkrequestack := ber.EncodeNull()
		retagged_enc_uplinkrequestack, tagErr_enc_uplinkrequestack := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_uplinkrequestack)
		if tagErr_enc_uplinkrequestack != nil {
			return nil, fmt.Errorf("encoding uplinkRequestAck: %w", tagErr_enc_uplinkrequestack)
		}
		enc_uplinkrequestack = retagged_enc_uplinkrequestack
		children = append(children, enc_uplinkrequestack...)
	}
	if v.UplinkReleaseIndication != nil {
		enc_uplinkreleaseindication := ber.EncodeNull()
		retagged_enc_uplinkreleaseindication, tagErr_enc_uplinkreleaseindication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uplinkreleaseindication)
		if tagErr_enc_uplinkreleaseindication != nil {
			return nil, fmt.Errorf("encoding uplinkReleaseIndication: %w", tagErr_enc_uplinkreleaseindication)
		}
		enc_uplinkreleaseindication = retagged_enc_uplinkreleaseindication
		children = append(children, enc_uplinkreleaseindication...)
	}
	if v.UplinkRejectCommand != nil {
		enc_uplinkrejectcommand := ber.EncodeNull()
		retagged_enc_uplinkrejectcommand, tagErr_enc_uplinkrejectcommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_uplinkrejectcommand)
		if tagErr_enc_uplinkrejectcommand != nil {
			return nil, fmt.Errorf("encoding uplinkRejectCommand: %w", tagErr_enc_uplinkrejectcommand)
		}
		enc_uplinkrejectcommand = retagged_enc_uplinkrejectcommand
		children = append(children, enc_uplinkrejectcommand...)
	}
	if v.UplinkSeizedCommand != nil {
		enc_uplinkseizedcommand := ber.EncodeNull()
		retagged_enc_uplinkseizedcommand, tagErr_enc_uplinkseizedcommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_uplinkseizedcommand)
		if tagErr_enc_uplinkseizedcommand != nil {
			return nil, fmt.Errorf("encoding uplinkSeizedCommand: %w", tagErr_enc_uplinkseizedcommand)
		}
		enc_uplinkseizedcommand = retagged_enc_uplinkseizedcommand
		children = append(children, enc_uplinkseizedcommand...)
	}
	if v.UplinkReleaseCommand != nil {
		enc_uplinkreleasecommand := ber.EncodeNull()
		retagged_enc_uplinkreleasecommand, tagErr_enc_uplinkreleasecommand := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_uplinkreleasecommand)
		if tagErr_enc_uplinkreleasecommand != nil {
			return nil, fmt.Errorf("encoding uplinkReleaseCommand: %w", tagErr_enc_uplinkreleasecommand)
		}
		enc_uplinkreleasecommand = retagged_enc_uplinkreleasecommand
		children = append(children, enc_uplinkreleasecommand...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.StateAttributes != nil {
		enc_stateattributes, err := v.StateAttributes.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding stateAttributes: %w", err)
		}
		retagged_enc_stateattributes, tagErr_enc_stateattributes := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_stateattributes)
		if tagErr_enc_stateattributes != nil {
			return nil, fmt.Errorf("encoding stateAttributes: %w", tagErr_enc_stateattributes)
		}
		enc_stateattributes = retagged_enc_stateattributes
		children = append(children, enc_stateattributes...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := ber.CheckEncodedValue(nil, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, fmt.Errorf("encoding talkerPriority: %w", tagErr_enc_talkerpriority)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := ber.CheckEncodedLength(nil, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		if encodeErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", encodeErr_enc_additionalinfo)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", tagErr_enc_additionalinfo)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.EmergencyModeResetCommandFlag != nil {
		enc_emergencymoderesetcommandflag := ber.EncodeNull()
		retagged_enc_emergencymoderesetcommandflag, tagErr_enc_emergencymoderesetcommandflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_emergencymoderesetcommandflag)
		if tagErr_enc_emergencymoderesetcommandflag != nil {
			return nil, fmt.Errorf("encoding emergencyModeResetCommandFlag: %w", tagErr_enc_emergencymoderesetcommandflag)
		}
		enc_emergencymoderesetcommandflag = retagged_enc_emergencymoderesetcommandflag
		children = append(children, enc_emergencymoderesetcommandflag...)
	}
	if v.SmRPUI != nil {
		if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
			if constraintErr := ber.CheckEncodedLength(nil, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		if encodeErr_enc_smrpui != nil {
			return nil, fmt.Errorf("encoding sm-RP-UI: %w", encodeErr_enc_smrpui)
		}
		retagged_enc_smrpui, tagErr_enc_smrpui := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_smrpui)
		if tagErr_enc_smrpui != nil {
			return nil, fmt.Errorf("encoding sm-RP-UI: %w", tagErr_enc_smrpui)
		}
		enc_smrpui = retagged_enc_smrpui
		children = append(children, enc_smrpui...)
	}
	if v.AnAPDU != nil {
		enc_anapdu, err := v.AnAPDU.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding an-APDU: %w", err)
		}
		retagged_enc_anapdu, tagErr_enc_anapdu := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_anapdu)
		if tagErr_enc_anapdu != nil {
			return nil, fmt.Errorf("encoding an-APDU: %w", tagErr_enc_anapdu)
		}
		enc_anapdu = retagged_enc_anapdu
		children = append(children, enc_anapdu...)
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
		return nil, fmt.Errorf("encoding ForwardGroupCallSignallingArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardGroupCallSignallingArg from BER/DER format.
func (v *ForwardGroupCallSignallingArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ForwardGroupCallSignallingArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ForwardGroupCallSignallingArg{}
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
		return fmt.Errorf("decoding ForwardGroupCallSignallingArg SEQUENCE: %w", err)
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
				val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI(val_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
				decodedTag_uplinkrequestack, n_uplinkrequestack, rawVal_uplinkrequestack, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uplinkRequestAck: %w", err)
				}
				if decodedTag_uplinkrequestack.Class != tag.ClassContextSpecific || decodedTag_uplinkrequestack.Number != 0 || decodedTag_uplinkrequestack.Constructed != false {
					return fmt.Errorf("decoding uplinkRequestAck: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uplinkrequestack)
				}
				if len(rawVal_uplinkrequestack) != 0 {
					return fmt.Errorf("decoding uplinkRequestAck: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkrequestack))
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
				decodedTag_uplinkreleaseindication, n_uplinkreleaseindication, rawVal_uplinkreleaseindication, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uplinkReleaseIndication: %w", err)
				}
				if decodedTag_uplinkreleaseindication.Class != tag.ClassContextSpecific || decodedTag_uplinkreleaseindication.Number != 1 || decodedTag_uplinkreleaseindication.Constructed != false {
					return fmt.Errorf("decoding uplinkReleaseIndication: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uplinkreleaseindication)
				}
				if len(rawVal_uplinkreleaseindication) != 0 {
					return fmt.Errorf("decoding uplinkReleaseIndication: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkreleaseindication))
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
				decodedTag_uplinkrejectcommand, n_uplinkrejectcommand, rawVal_uplinkrejectcommand, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uplinkRejectCommand: %w", err)
				}
				if decodedTag_uplinkrejectcommand.Class != tag.ClassContextSpecific || decodedTag_uplinkrejectcommand.Number != 2 || decodedTag_uplinkrejectcommand.Constructed != false {
					return fmt.Errorf("decoding uplinkRejectCommand: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uplinkrejectcommand)
				}
				if len(rawVal_uplinkrejectcommand) != 0 {
					return fmt.Errorf("decoding uplinkRejectCommand: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkrejectcommand))
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
				decodedTag_uplinkseizedcommand, n_uplinkseizedcommand, rawVal_uplinkseizedcommand, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uplinkSeizedCommand: %w", err)
				}
				if decodedTag_uplinkseizedcommand.Class != tag.ClassContextSpecific || decodedTag_uplinkseizedcommand.Number != 3 || decodedTag_uplinkseizedcommand.Constructed != false {
					return fmt.Errorf("decoding uplinkSeizedCommand: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uplinkseizedcommand)
				}
				if len(rawVal_uplinkseizedcommand) != 0 {
					return fmt.Errorf("decoding uplinkSeizedCommand: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkseizedcommand))
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
				decodedTag_uplinkreleasecommand, n_uplinkreleasecommand, rawVal_uplinkreleasecommand, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uplinkReleaseCommand: %w", err)
				}
				if decodedTag_uplinkreleasecommand.Class != tag.ClassContextSpecific || decodedTag_uplinkreleasecommand.Number != 4 || decodedTag_uplinkreleasecommand.Constructed != false {
					return fmt.Errorf("decoding uplinkReleaseCommand: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uplinkreleasecommand)
				}
				if len(rawVal_uplinkreleasecommand) != 0 {
					return fmt.Errorf("decoding uplinkReleaseCommand: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkreleasecommand))
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
				decodedTag_stateattributes, n_stateattributes, rawVal_stateattributes, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding stateAttributes: %w", err)
				}
				if decodedTag_stateattributes.Class != tag.ClassContextSpecific || decodedTag_stateattributes.Number != 5 || decodedTag_stateattributes.Constructed != true {
					return fmt.Errorf("decoding stateAttributes: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_stateattributes)
				}
				reconstructed_stateattributes, reconstructionErr_stateattributes := ber.EncodeSequence(rawVal_stateattributes)
				if reconstructionErr_stateattributes != nil {
					return fmt.Errorf("decoding stateAttributes: %w", reconstructionErr_stateattributes)
				}
				var dec_stateattributes StateAttributes
				if unmErr := dec_stateattributes.UnmarshalBER(reconstructed_stateattributes, ber.ChildDecodeOptions(opts, "stateAttributes")...); unmErr != nil {
					return fmt.Errorf("decoding stateAttributes: %w", unmErr)
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
				decodedTag_talkerpriority, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding talkerPriority: %w", err)
				}
				if decodedTag_talkerpriority.Class != tag.ClassContextSpecific || decodedTag_talkerpriority.Number != 6 || decodedTag_talkerpriority.Constructed != false {
					return fmt.Errorf("decoding talkerPriority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_talkerpriority)
				}
				decVal_talkerpriority, intErr := ber.DecodeEnumeratedValue(rawVal_talkerpriority)
				if intErr != nil {
					return fmt.Errorf("decoding talkerPriority: %w", intErr)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				if offset < 0 || offset >
					len(content) || n_talkerpriority < 0 || n_talkerpriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_talkerpriority
				if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
					if constraintErr := ber.CheckDecodedValue(opts, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
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
				decodedTag_additionalinfo, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding additionalInfo: %w", err)
				}
				if decodedTag_additionalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalinfo.Number != 7 {
					return fmt.Errorf("decoding additionalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalinfo)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalinfo.Constructed, rawVal_additionalinfo, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsErr)
				}
				bsBitLength_additionalinfo, bsLenErr_additionalinfo := ber.BitStringBitLength(len(bsBytes_additionalinfo), bsUnused_additionalinfo)
				if bsLenErr_additionalinfo != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsLenErr_additionalinfo)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: bsBitLength_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				if offset < 0 || offset >
					len(content) || n_additionalinfo < 0 || n_additionalinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalinfo
				if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
					if constraintErr := ber.CheckDecodedLength(opts, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
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
				decodedTag_emergencymoderesetcommandflag, n_emergencymoderesetcommandflag, rawVal_emergencymoderesetcommandflag, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding emergencyModeResetCommandFlag: %w", err)
				}
				if decodedTag_emergencymoderesetcommandflag.Class != tag.ClassContextSpecific || decodedTag_emergencymoderesetcommandflag.Number != 8 || decodedTag_emergencymoderesetcommandflag.Constructed != false {
					return fmt.Errorf("decoding emergencyModeResetCommandFlag: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_emergencymoderesetcommandflag)
				}
				if len(rawVal_emergencymoderesetcommandflag) != 0 {
					return fmt.Errorf("decoding emergencyModeResetCommandFlag: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_emergencymoderesetcommandflag))
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
				decodedTag_smrpui, n_smrpui, rawVal_smrpui, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sm-RP-UI: %w", err)
				}
				if decodedTag_smrpui.Class != tag.ClassContextSpecific || decodedTag_smrpui.Number != 9 {
					return fmt.Errorf("decoding sm-RP-UI: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_smrpui)
				}
				decVal_smrpui, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_smrpui.Constructed, rawVal_smrpui, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding sm-RP-UI: %w", octetErr)
				}
				tmp_smrpui := SignalInfo(decVal_smrpui)
				v.SmRPUI = &tmp_smrpui
				if offset < 0 || offset >
					len(content) || n_smrpui < 0 || n_smrpui > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_smrpui
				if len(*v.SmRPUI) < 1 || len(*v.SmRPUI) > 200 {
					if constraintErr := ber.CheckDecodedLength(opts, "sm-RP-UI", "SIZE (1..200)", len(*v.SmRPUI)); constraintErr != nil {
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
				decodedTag_anapdu, n_anapdu, rawVal_anapdu, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding an-APDU: %w", err)
				}
				if decodedTag_anapdu.Class != tag.ClassContextSpecific || decodedTag_anapdu.Number != 10 || decodedTag_anapdu.Constructed != true {
					return fmt.Errorf("decoding an-APDU: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_anapdu)
				}
				reconstructed_anapdu, reconstructionErr_anapdu := ber.EncodeSequence(rawVal_anapdu)
				if reconstructionErr_anapdu != nil {
					return fmt.Errorf("decoding an-APDU: %w", reconstructionErr_anapdu)
				}
				var dec_anapdu AccessNetworkSignalInfo
				if unmErr := dec_anapdu.UnmarshalBER(reconstructed_anapdu, ber.ChildDecodeOptions(opts, "an-APDU")...); unmErr != nil {
					return fmt.Errorf("decoding an-APDU: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardGroupCallSignallingArg", Cause: extErr_}
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
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: ProcessGroupCallSignallingArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
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
			return nil, fmt.Errorf("encoding uplinkRequest: %w", tagErr_enc_uplinkrequest)
		}
		enc_uplinkrequest = retagged_enc_uplinkrequest
		children = append(children, enc_uplinkrequest...)
	}
	if v.UplinkReleaseIndication != nil {
		enc_uplinkreleaseindication := ber.EncodeNull()
		retagged_enc_uplinkreleaseindication, tagErr_enc_uplinkreleaseindication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uplinkreleaseindication)
		if tagErr_enc_uplinkreleaseindication != nil {
			return nil, fmt.Errorf("encoding uplinkReleaseIndication: %w", tagErr_enc_uplinkreleaseindication)
		}
		enc_uplinkreleaseindication = retagged_enc_uplinkreleaseindication
		children = append(children, enc_uplinkreleaseindication...)
	}
	if v.ReleaseGroupCall != nil {
		enc_releasegroupcall := ber.EncodeNull()
		retagged_enc_releasegroupcall, tagErr_enc_releasegroupcall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_releasegroupcall)
		if tagErr_enc_releasegroupcall != nil {
			return nil, fmt.Errorf("encoding releaseGroupCall: %w", tagErr_enc_releasegroupcall)
		}
		enc_releasegroupcall = retagged_enc_releasegroupcall
		children = append(children, enc_releasegroupcall...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := ber.CheckEncodedValue(opts, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, fmt.Errorf("encoding talkerPriority: %w", tagErr_enc_talkerpriority)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := ber.CheckEncodedLength(opts, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		if encodeErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", encodeErr_enc_additionalinfo)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", tagErr_enc_additionalinfo)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.EmergencyModeResetCommandFlag != nil {
		enc_emergencymoderesetcommandflag := ber.EncodeNull()
		retagged_enc_emergencymoderesetcommandflag, tagErr_enc_emergencymoderesetcommandflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_emergencymoderesetcommandflag)
		if tagErr_enc_emergencymoderesetcommandflag != nil {
			return nil, fmt.Errorf("encoding emergencyModeResetCommandFlag: %w", tagErr_enc_emergencymoderesetcommandflag)
		}
		enc_emergencymoderesetcommandflag = retagged_enc_emergencymoderesetcommandflag
		children = append(children, enc_emergencymoderesetcommandflag...)
	}
	if v.AnAPDU != nil {
		enc_anapdu, err := v.AnAPDU.MarshalBER(ber.ChildEncodeOptions(opts, "an-APDU")...)
		if err != nil {
			return nil, fmt.Errorf("encoding an-APDU: %w", err)
		}
		retagged_enc_anapdu, tagErr_enc_anapdu := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_anapdu)
		if tagErr_enc_anapdu != nil {
			return nil, fmt.Errorf("encoding an-APDU: %w", tagErr_enc_anapdu)
		}
		enc_anapdu = retagged_enc_anapdu
		children = append(children, enc_anapdu...)
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

// MarshalDER encodes ProcessGroupCallSignallingArg to DER format.
func (v *ProcessGroupCallSignallingArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ProcessGroupCallSignallingArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.UplinkRequest != nil {
		enc_uplinkrequest := ber.EncodeNull()
		retagged_enc_uplinkrequest, tagErr_enc_uplinkrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_uplinkrequest)
		if tagErr_enc_uplinkrequest != nil {
			return nil, fmt.Errorf("encoding uplinkRequest: %w", tagErr_enc_uplinkrequest)
		}
		enc_uplinkrequest = retagged_enc_uplinkrequest
		children = append(children, enc_uplinkrequest...)
	}
	if v.UplinkReleaseIndication != nil {
		enc_uplinkreleaseindication := ber.EncodeNull()
		retagged_enc_uplinkreleaseindication, tagErr_enc_uplinkreleaseindication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_uplinkreleaseindication)
		if tagErr_enc_uplinkreleaseindication != nil {
			return nil, fmt.Errorf("encoding uplinkReleaseIndication: %w", tagErr_enc_uplinkreleaseindication)
		}
		enc_uplinkreleaseindication = retagged_enc_uplinkreleaseindication
		children = append(children, enc_uplinkreleaseindication...)
	}
	if v.ReleaseGroupCall != nil {
		enc_releasegroupcall := ber.EncodeNull()
		retagged_enc_releasegroupcall, tagErr_enc_releasegroupcall := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_releasegroupcall)
		if tagErr_enc_releasegroupcall != nil {
			return nil, fmt.Errorf("encoding releaseGroupCall: %w", tagErr_enc_releasegroupcall)
		}
		enc_releasegroupcall = retagged_enc_releasegroupcall
		children = append(children, enc_releasegroupcall...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := ber.CheckEncodedValue(nil, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, fmt.Errorf("encoding talkerPriority: %w", tagErr_enc_talkerpriority)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := ber.CheckEncodedLength(nil, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		if encodeErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", encodeErr_enc_additionalinfo)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", tagErr_enc_additionalinfo)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.EmergencyModeResetCommandFlag != nil {
		enc_emergencymoderesetcommandflag := ber.EncodeNull()
		retagged_enc_emergencymoderesetcommandflag, tagErr_enc_emergencymoderesetcommandflag := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_emergencymoderesetcommandflag)
		if tagErr_enc_emergencymoderesetcommandflag != nil {
			return nil, fmt.Errorf("encoding emergencyModeResetCommandFlag: %w", tagErr_enc_emergencymoderesetcommandflag)
		}
		enc_emergencymoderesetcommandflag = retagged_enc_emergencymoderesetcommandflag
		children = append(children, enc_emergencymoderesetcommandflag...)
	}
	if v.AnAPDU != nil {
		enc_anapdu, err := v.AnAPDU.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding an-APDU: %w", err)
		}
		retagged_enc_anapdu, tagErr_enc_anapdu := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_anapdu)
		if tagErr_enc_anapdu != nil {
			return nil, fmt.Errorf("encoding an-APDU: %w", tagErr_enc_anapdu)
		}
		enc_anapdu = retagged_enc_anapdu
		children = append(children, enc_anapdu...)
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
		return nil, fmt.Errorf("encoding ProcessGroupCallSignallingArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ProcessGroupCallSignallingArg from BER/DER format.
func (v *ProcessGroupCallSignallingArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ProcessGroupCallSignallingArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ProcessGroupCallSignallingArg{}
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
		return fmt.Errorf("decoding ProcessGroupCallSignallingArg SEQUENCE: %w", err)
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
				decodedTag_uplinkrequest, n_uplinkrequest, rawVal_uplinkrequest, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uplinkRequest: %w", err)
				}
				if decodedTag_uplinkrequest.Class != tag.ClassContextSpecific || decodedTag_uplinkrequest.Number != 0 || decodedTag_uplinkrequest.Constructed != false {
					return fmt.Errorf("decoding uplinkRequest: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uplinkrequest)
				}
				if len(rawVal_uplinkrequest) != 0 {
					return fmt.Errorf("decoding uplinkRequest: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkrequest))
				}
				v.UplinkRequest = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_uplinkrequest < 0 || n_uplinkrequest > len(content[offset:]) {
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
				decodedTag_uplinkreleaseindication, n_uplinkreleaseindication, rawVal_uplinkreleaseindication, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uplinkReleaseIndication: %w", err)
				}
				if decodedTag_uplinkreleaseindication.Class != tag.ClassContextSpecific || decodedTag_uplinkreleaseindication.Number != 1 || decodedTag_uplinkreleaseindication.Constructed != false {
					return fmt.Errorf("decoding uplinkReleaseIndication: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uplinkreleaseindication)
				}
				if len(rawVal_uplinkreleaseindication) != 0 {
					return fmt.Errorf("decoding uplinkReleaseIndication: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkreleaseindication))
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
				decodedTag_releasegroupcall, n_releasegroupcall, rawVal_releasegroupcall, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding releaseGroupCall: %w", err)
				}
				if decodedTag_releasegroupcall.Class != tag.ClassContextSpecific || decodedTag_releasegroupcall.Number != 2 || decodedTag_releasegroupcall.Constructed != false {
					return fmt.Errorf("decoding releaseGroupCall: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_releasegroupcall)
				}
				if len(rawVal_releasegroupcall) != 0 {
					return fmt.Errorf("decoding releaseGroupCall: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_releasegroupcall))
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
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
				decodedTag_talkerpriority, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding talkerPriority: %w", err)
				}
				if decodedTag_talkerpriority.Class != tag.ClassContextSpecific || decodedTag_talkerpriority.Number != 3 || decodedTag_talkerpriority.Constructed != false {
					return fmt.Errorf("decoding talkerPriority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_talkerpriority)
				}
				decVal_talkerpriority, intErr := ber.DecodeEnumeratedValue(rawVal_talkerpriority)
				if intErr != nil {
					return fmt.Errorf("decoding talkerPriority: %w", intErr)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				if offset < 0 || offset >
					len(content) || n_talkerpriority < 0 || n_talkerpriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_talkerpriority
				if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
					if constraintErr := ber.CheckDecodedValue(opts, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
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
				decodedTag_additionalinfo, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding additionalInfo: %w", err)
				}
				if decodedTag_additionalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalinfo.Number != 4 {
					return fmt.Errorf("decoding additionalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalinfo)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalinfo.Constructed, rawVal_additionalinfo, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsErr)
				}
				bsBitLength_additionalinfo, bsLenErr_additionalinfo := ber.BitStringBitLength(len(bsBytes_additionalinfo), bsUnused_additionalinfo)
				if bsLenErr_additionalinfo != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsLenErr_additionalinfo)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: bsBitLength_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				if offset < 0 || offset >
					len(content) || n_additionalinfo < 0 || n_additionalinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalinfo
				if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
					if constraintErr := ber.CheckDecodedLength(opts, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
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
				decodedTag_emergencymoderesetcommandflag, n_emergencymoderesetcommandflag, rawVal_emergencymoderesetcommandflag, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding emergencyModeResetCommandFlag: %w", err)
				}
				if decodedTag_emergencymoderesetcommandflag.Class != tag.ClassContextSpecific || decodedTag_emergencymoderesetcommandflag.Number != 5 || decodedTag_emergencymoderesetcommandflag.Constructed != false {
					return fmt.Errorf("decoding emergencyModeResetCommandFlag: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_emergencymoderesetcommandflag)
				}
				if len(rawVal_emergencymoderesetcommandflag) != 0 {
					return fmt.Errorf("decoding emergencyModeResetCommandFlag: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_emergencymoderesetcommandflag))
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
				decodedTag_anapdu, n_anapdu, rawVal_anapdu, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding an-APDU: %w", err)
				}
				if decodedTag_anapdu.Class != tag.ClassContextSpecific || decodedTag_anapdu.Number != 6 || decodedTag_anapdu.Constructed != true {
					return fmt.Errorf("decoding an-APDU: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_anapdu)
				}
				reconstructed_anapdu, reconstructionErr_anapdu := ber.EncodeSequence(rawVal_anapdu)
				if reconstructionErr_anapdu != nil {
					return fmt.Errorf("decoding an-APDU: %w", reconstructionErr_anapdu)
				}
				var dec_anapdu AccessNetworkSignalInfo
				if unmErr := dec_anapdu.UnmarshalBER(reconstructed_anapdu, ber.ChildDecodeOptions(opts, "an-APDU")...); unmErr != nil {
					return fmt.Errorf("decoding an-APDU: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProcessGroupCallSignallingArg", Cause: extErr_}
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
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: StateAttributes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
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
			return nil, fmt.Errorf("encoding downlinkAttached: %w", tagErr_enc_downlinkattached)
		}
		enc_downlinkattached = retagged_enc_downlinkattached
		children = append(children, enc_downlinkattached...)
	}
	if v.UplinkAttached != nil {
		enc_uplinkattached := ber.EncodeNull()
		retagged_enc_uplinkattached, tagErr_enc_uplinkattached := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_uplinkattached)
		if tagErr_enc_uplinkattached != nil {
			return nil, fmt.Errorf("encoding uplinkAttached: %w", tagErr_enc_uplinkattached)
		}
		enc_uplinkattached = retagged_enc_uplinkattached
		children = append(children, enc_uplinkattached...)
	}
	if v.DualCommunication != nil {
		enc_dualcommunication := ber.EncodeNull()
		retagged_enc_dualcommunication, tagErr_enc_dualcommunication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_dualcommunication)
		if tagErr_enc_dualcommunication != nil {
			return nil, fmt.Errorf("encoding dualCommunication: %w", tagErr_enc_dualcommunication)
		}
		enc_dualcommunication = retagged_enc_dualcommunication
		children = append(children, enc_dualcommunication...)
	}
	if v.CallOriginator != nil {
		enc_calloriginator := ber.EncodeNull()
		retagged_enc_calloriginator, tagErr_enc_calloriginator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_calloriginator)
		if tagErr_enc_calloriginator != nil {
			return nil, fmt.Errorf("encoding callOriginator: %w", tagErr_enc_calloriginator)
		}
		enc_calloriginator = retagged_enc_calloriginator
		children = append(children, enc_calloriginator...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes StateAttributes to DER format.
func (v *StateAttributes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: StateAttributes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.DownlinkAttached != nil {
		enc_downlinkattached := ber.EncodeNull()
		retagged_enc_downlinkattached, tagErr_enc_downlinkattached := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_downlinkattached)
		if tagErr_enc_downlinkattached != nil {
			return nil, fmt.Errorf("encoding downlinkAttached: %w", tagErr_enc_downlinkattached)
		}
		enc_downlinkattached = retagged_enc_downlinkattached
		children = append(children, enc_downlinkattached...)
	}
	if v.UplinkAttached != nil {
		enc_uplinkattached := ber.EncodeNull()
		retagged_enc_uplinkattached, tagErr_enc_uplinkattached := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_uplinkattached)
		if tagErr_enc_uplinkattached != nil {
			return nil, fmt.Errorf("encoding uplinkAttached: %w", tagErr_enc_uplinkattached)
		}
		enc_uplinkattached = retagged_enc_uplinkattached
		children = append(children, enc_uplinkattached...)
	}
	if v.DualCommunication != nil {
		enc_dualcommunication := ber.EncodeNull()
		retagged_enc_dualcommunication, tagErr_enc_dualcommunication := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_dualcommunication)
		if tagErr_enc_dualcommunication != nil {
			return nil, fmt.Errorf("encoding dualCommunication: %w", tagErr_enc_dualcommunication)
		}
		enc_dualcommunication = retagged_enc_dualcommunication
		children = append(children, enc_dualcommunication...)
	}
	if v.CallOriginator != nil {
		enc_calloriginator := ber.EncodeNull()
		retagged_enc_calloriginator, tagErr_enc_calloriginator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_calloriginator)
		if tagErr_enc_calloriginator != nil {
			return nil, fmt.Errorf("encoding callOriginator: %w", tagErr_enc_calloriginator)
		}
		enc_calloriginator = retagged_enc_calloriginator
		children = append(children, enc_calloriginator...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding StateAttributes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes StateAttributes from BER/DER format.
func (v *StateAttributes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: StateAttributes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = StateAttributes{}
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
		return fmt.Errorf("decoding StateAttributes SEQUENCE: %w", err)
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
				decodedTag_downlinkattached, n_downlinkattached, rawVal_downlinkattached, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding downlinkAttached: %w", err)
				}
				if decodedTag_downlinkattached.Class != tag.ClassContextSpecific || decodedTag_downlinkattached.Number != 5 || decodedTag_downlinkattached.Constructed != false {
					return fmt.Errorf("decoding downlinkAttached: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_downlinkattached)
				}
				if len(rawVal_downlinkattached) != 0 {
					return fmt.Errorf("decoding downlinkAttached: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_downlinkattached))
				}
				v.DownlinkAttached = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_downlinkattached < 0 || n_downlinkattached >
					len(content[offset:]) {
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
				decodedTag_uplinkattached, n_uplinkattached, rawVal_uplinkattached, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding uplinkAttached: %w", err)
				}
				if decodedTag_uplinkattached.Class != tag.ClassContextSpecific || decodedTag_uplinkattached.Number != 6 || decodedTag_uplinkattached.Constructed != false {
					return fmt.Errorf("decoding uplinkAttached: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_uplinkattached)
				}
				if len(rawVal_uplinkattached) != 0 {
					return fmt.Errorf("decoding uplinkAttached: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_uplinkattached))
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
				decodedTag_dualcommunication, n_dualcommunication, rawVal_dualcommunication, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding dualCommunication: %w", err)
				}
				if decodedTag_dualcommunication.Class != tag.ClassContextSpecific || decodedTag_dualcommunication.Number != 7 || decodedTag_dualcommunication.Constructed != false {
					return fmt.Errorf("decoding dualCommunication: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_dualcommunication)
				}
				if len(rawVal_dualcommunication) != 0 {
					return fmt.Errorf("decoding dualCommunication: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_dualcommunication))
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
				decodedTag_calloriginator, n_calloriginator, rawVal_calloriginator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding callOriginator: %w", err)
				}
				if decodedTag_calloriginator.Class != tag.ClassContextSpecific || decodedTag_calloriginator.Number != 8 || decodedTag_calloriginator.Constructed != false {
					return fmt.Errorf("decoding callOriginator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_calloriginator)
				}
				if len(rawVal_calloriginator) != 0 {
					return fmt.Errorf("decoding callOriginator: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_calloriginator))
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
		return &ber.DecodeError{Offset: offset, TypeName: "StateAttributes", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SendGroupCallInfoArg to BER format.
func (v *SendGroupCallInfoArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallInfoArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SendGroupCallInfoArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_requestedinfo := ber.EncodeEnumerated(int64(v.RequestedInfo))
	children = append(children, enc_requestedinfo...)
	if len(v.GroupId) < 4 || len(v.GroupId) > 4 {
		if constraintErr := ber.CheckEncodedLength(opts, "groupId", "SIZE (4)", len(v.GroupId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_groupid, encodeErr_enc_groupid := ber.EncodeOctetString([]byte(v.GroupId))
	if encodeErr_enc_groupid != nil {
		return nil, fmt.Errorf("encoding groupId: %w", encodeErr_enc_groupid)
	}
	children = append(children, enc_groupid...)
	if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
		if constraintErr := ber.CheckEncodedLength(opts, "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(v.Teleservice))
	if encodeErr_enc_teleservice != nil {
		return nil, fmt.Errorf("encoding teleservice: %w", encodeErr_enc_teleservice)
	}
	children = append(children, enc_teleservice...)
	if v.CellId != nil {
		if len(*v.CellId) < 5 || len(*v.CellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "cellId", "SIZE (5..7)", len(*v.CellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cellid, encodeErr_enc_cellid := ber.EncodeOctetString([]byte(*v.CellId))
		if encodeErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", encodeErr_enc_cellid)
		}
		retagged_enc_cellid, tagErr_enc_cellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cellid)
		if tagErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", tagErr_enc_cellid)
		}
		enc_cellid = retagged_enc_cellid
		children = append(children, enc_cellid...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Tmsi != nil {
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(opts, "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tmsi, encodeErr_enc_tmsi := ber.EncodeOctetString([]byte(*v.Tmsi))
		if encodeErr_enc_tmsi != nil {
			return nil, fmt.Errorf("encoding tmsi: %w", encodeErr_enc_tmsi)
		}
		retagged_enc_tmsi, tagErr_enc_tmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tmsi)
		if tagErr_enc_tmsi != nil {
			return nil, fmt.Errorf("encoding tmsi: %w", tagErr_enc_tmsi)
		}
		enc_tmsi = retagged_enc_tmsi
		children = append(children, enc_tmsi...)
	}
	if v.AdditionalInfo != nil {
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := ber.CheckEncodedLength(opts, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		if encodeErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", encodeErr_enc_additionalinfo)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", tagErr_enc_additionalinfo)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := ber.CheckEncodedValue(opts, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, fmt.Errorf("encoding talkerPriority: %w", tagErr_enc_talkerpriority)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.Cksn != nil {
		if len(*v.Cksn) < 1 || len(*v.Cksn) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "cksn", "SIZE (1)", len(*v.Cksn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cksn, encodeErr_enc_cksn := ber.EncodeOctetString([]byte(*v.Cksn))
		if encodeErr_enc_cksn != nil {
			return nil, fmt.Errorf("encoding cksn: %w", encodeErr_enc_cksn)
		}
		retagged_enc_cksn, tagErr_enc_cksn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_cksn)
		if tagErr_enc_cksn != nil {
			return nil, fmt.Errorf("encoding cksn: %w", tagErr_enc_cksn)
		}
		enc_cksn = retagged_enc_cksn
		children = append(children, enc_cksn...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
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

// MarshalDER encodes SendGroupCallInfoArg to DER format.
func (v *SendGroupCallInfoArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallInfoArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_requestedinfo := ber.EncodeEnumerated(int64(v.RequestedInfo))
	children = append(children, enc_requestedinfo...)
	if len(v.GroupId) < 4 || len(v.GroupId) > 4 {
		if constraintErr := ber.CheckEncodedLength(nil, "groupId", "SIZE (4)", len(v.GroupId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_groupid, encodeErr_enc_groupid := ber.EncodeOctetString([]byte(v.GroupId))
	if encodeErr_enc_groupid != nil {
		return nil, fmt.Errorf("encoding groupId: %w", encodeErr_enc_groupid)
	}
	children = append(children, enc_groupid...)
	if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
		if constraintErr := ber.CheckEncodedLength(nil, "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(v.Teleservice))
	if encodeErr_enc_teleservice != nil {
		return nil, fmt.Errorf("encoding teleservice: %w", encodeErr_enc_teleservice)
	}
	children = append(children, enc_teleservice...)
	if v.CellId != nil {
		if len(*v.CellId) < 5 || len(*v.CellId) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, "cellId", "SIZE (5..7)", len(*v.CellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cellid, encodeErr_enc_cellid := ber.EncodeOctetString([]byte(*v.CellId))
		if encodeErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", encodeErr_enc_cellid)
		}
		retagged_enc_cellid, tagErr_enc_cellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_cellid)
		if tagErr_enc_cellid != nil {
			return nil, fmt.Errorf("encoding cellId: %w", tagErr_enc_cellid)
		}
		enc_cellid = retagged_enc_cellid
		children = append(children, enc_cellid...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.Tmsi != nil {
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(nil, "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tmsi, encodeErr_enc_tmsi := ber.EncodeOctetString([]byte(*v.Tmsi))
		if encodeErr_enc_tmsi != nil {
			return nil, fmt.Errorf("encoding tmsi: %w", encodeErr_enc_tmsi)
		}
		retagged_enc_tmsi, tagErr_enc_tmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tmsi)
		if tagErr_enc_tmsi != nil {
			return nil, fmt.Errorf("encoding tmsi: %w", tagErr_enc_tmsi)
		}
		enc_tmsi = retagged_enc_tmsi
		children = append(children, enc_tmsi...)
	}
	if v.AdditionalInfo != nil {
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := ber.CheckEncodedLength(nil, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		if encodeErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", encodeErr_enc_additionalinfo)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", tagErr_enc_additionalinfo)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.TalkerPriority != nil {
		if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
			if constraintErr := ber.CheckEncodedValue(nil, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		retagged_enc_talkerpriority, tagErr_enc_talkerpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_talkerpriority)
		if tagErr_enc_talkerpriority != nil {
			return nil, fmt.Errorf("encoding talkerPriority: %w", tagErr_enc_talkerpriority)
		}
		enc_talkerpriority = retagged_enc_talkerpriority
		children = append(children, enc_talkerpriority...)
	}
	if v.Cksn != nil {
		if len(*v.Cksn) < 1 || len(*v.Cksn) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "cksn", "SIZE (1)", len(*v.Cksn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cksn, encodeErr_enc_cksn := ber.EncodeOctetString([]byte(*v.Cksn))
		if encodeErr_enc_cksn != nil {
			return nil, fmt.Errorf("encoding cksn: %w", encodeErr_enc_cksn)
		}
		retagged_enc_cksn, tagErr_enc_cksn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_cksn)
		if tagErr_enc_cksn != nil {
			return nil, fmt.Errorf("encoding cksn: %w", tagErr_enc_cksn)
		}
		enc_cksn = retagged_enc_cksn
		children = append(children, enc_cksn...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
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
		return nil, fmt.Errorf("encoding SendGroupCallInfoArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SendGroupCallInfoArg from BER/DER format.
func (v *SendGroupCallInfoArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SendGroupCallInfoArg destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SendGroupCallInfoArg{}
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
		return fmt.Errorf("decoding SendGroupCallInfoArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendGroupCallInfoArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode requestedInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field requestedInfo")
	}
	val_requestedinfo, n, err := ber.DecodeEnumerated(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding requestedInfo: %w", err)
	}
	v.RequestedInfo = GRRequestedInfo(val_requestedinfo)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	// Decode groupId
	if offset >= len(content) {
		return fmt.Errorf("missing required field groupId")
	}
	val_groupid, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding groupId: %w", err)
	}
	v.GroupId = LongGroupId(val_groupid)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.GroupId) < 4 || len(v.GroupId) > 4 {
		if constraintErr := ber.CheckDecodedLength(opts, "groupId", "SIZE (4)", len(v.GroupId)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode teleservice
	if offset >= len(content) {
		return fmt.Errorf("missing required field teleservice")
	}
	val_teleservice, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding teleservice: %w", err)
	}
	v.Teleservice = ExtTeleserviceCode(val_teleservice)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Teleservice) < 1 || len(v.Teleservice) > 5 {
		if constraintErr := ber.CheckDecodedLength(opts, "teleservice", "SIZE (1..5)", len(v.Teleservice)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode cellId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_cellid, n_cellid, rawVal_cellid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cellId: %w", err)
				}
				if decodedTag_cellid.Class != tag.ClassContextSpecific || decodedTag_cellid.Number != 0 {
					return fmt.Errorf("decoding cellId: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cellid)
				}
				decVal_cellid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cellid.Constructed, rawVal_cellid, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding cellId: %w", octetErr)
				}
				tmp_cellid := GlobalCellId(decVal_cellid)
				v.CellId = &tmp_cellid
				if offset < 0 || offset >
					len(content) || n_cellid < 0 || n_cellid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cellid
				if len(*v.CellId) < 5 || len(*v.CellId) > 7 {
					if constraintErr := ber.CheckDecodedLength(opts, "cellId", "SIZE (5..7)", len(*v.CellId)); constraintErr != nil {
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
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 1 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding imsi: %w", octetErr)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
				decodedTag_tmsi, n_tmsi, rawVal_tmsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding tmsi: %w", err)
				}
				if decodedTag_tmsi.Class != tag.ClassContextSpecific || decodedTag_tmsi.Number != 2 {
					return fmt.Errorf("decoding tmsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tmsi)
				}
				decVal_tmsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tmsi.Constructed, rawVal_tmsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding tmsi: %w", octetErr)
				}
				tmp_tmsi := TMSI(decVal_tmsi)
				v.Tmsi = &tmp_tmsi
				if offset < 0 || offset >
					len(content) || n_tmsi < 0 || n_tmsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tmsi
				if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
					if constraintErr := ber.CheckDecodedLength(opts, "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
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
				decodedTag_additionalinfo, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding additionalInfo: %w", err)
				}
				if decodedTag_additionalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalinfo.Number != 3 {
					return fmt.Errorf("decoding additionalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalinfo)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalinfo.Constructed, rawVal_additionalinfo, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsErr)
				}
				bsBitLength_additionalinfo, bsLenErr_additionalinfo := ber.BitStringBitLength(len(bsBytes_additionalinfo), bsUnused_additionalinfo)
				if bsLenErr_additionalinfo != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsLenErr_additionalinfo)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: bsBitLength_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				if offset < 0 || offset >
					len(content) || n_additionalinfo < 0 || n_additionalinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalinfo
				if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
					if constraintErr := ber.CheckDecodedLength(opts, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
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
				decodedTag_talkerpriority, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding talkerPriority: %w", err)
				}
				if decodedTag_talkerpriority.Class != tag.ClassContextSpecific || decodedTag_talkerpriority.Number != 4 || decodedTag_talkerpriority.Constructed != false {
					return fmt.Errorf("decoding talkerPriority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_talkerpriority)
				}
				decVal_talkerpriority, intErr := ber.DecodeEnumeratedValue(rawVal_talkerpriority)
				if intErr != nil {
					return fmt.Errorf("decoding talkerPriority: %w", intErr)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				if offset < 0 || offset >
					len(content) || n_talkerpriority < 0 || n_talkerpriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_talkerpriority
				if int64(*v.TalkerPriority) != 0 && int64(*v.TalkerPriority) != 1 && int64(*v.TalkerPriority) != 2 {
					if constraintErr := ber.CheckDecodedValue(opts, "talkerPriority", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.TalkerPriority))); constraintErr != nil {
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
				decodedTag_cksn, n_cksn, rawVal_cksn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cksn: %w", err)
				}
				if decodedTag_cksn.Class != tag.ClassContextSpecific || decodedTag_cksn.Number != 5 {
					return fmt.Errorf("decoding cksn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_cksn)
				}
				decVal_cksn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cksn.Constructed, rawVal_cksn, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding cksn: %w", octetErr)
				}
				tmp_cksn := Cksn(decVal_cksn)
				v.Cksn = &tmp_cksn
				if offset < 0 || offset >
					len(content) || n_cksn < 0 || n_cksn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cksn
				if len(*v.Cksn) < 1 || len(*v.Cksn) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "cksn", "SIZE (1)", len(*v.Cksn)); constraintErr != nil {
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
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 6 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallInfoArg", Cause: extErr_}
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
	opts, commitReports := ber.StageEncodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallInfoRes receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SendGroupCallInfoRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.AnchorMSCAddress != nil {
		if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "anchorMSC-Address", "SIZE (1..9)", len(*v.AnchorMSCAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "anchorMSC-Address", "SIZE (1..20)", len(*v.AnchorMSCAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_anchormscaddress, encodeErr_enc_anchormscaddress := ber.EncodeOctetString([]byte(*v.AnchorMSCAddress))
		if encodeErr_enc_anchormscaddress != nil {
			return nil, fmt.Errorf("encoding anchorMSC-Address: %w", encodeErr_enc_anchormscaddress)
		}
		retagged_enc_anchormscaddress, tagErr_enc_anchormscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_anchormscaddress)
		if tagErr_enc_anchormscaddress != nil {
			return nil, fmt.Errorf("encoding anchorMSC-Address: %w", tagErr_enc_anchormscaddress)
		}
		enc_anchormscaddress = retagged_enc_anchormscaddress
		children = append(children, enc_anchormscaddress...)
	}
	if v.AsciCallReference != nil {
		if len(*v.AsciCallReference) < 1 || len(*v.AsciCallReference) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "asciCallReference", "SIZE (1..8)", len(*v.AsciCallReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ascicallreference, encodeErr_enc_ascicallreference := ber.EncodeOctetString([]byte(*v.AsciCallReference))
		if encodeErr_enc_ascicallreference != nil {
			return nil, fmt.Errorf("encoding asciCallReference: %w", encodeErr_enc_ascicallreference)
		}
		retagged_enc_ascicallreference, tagErr_enc_ascicallreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ascicallreference)
		if tagErr_enc_ascicallreference != nil {
			return nil, fmt.Errorf("encoding asciCallReference: %w", tagErr_enc_ascicallreference)
		}
		enc_ascicallreference = retagged_enc_ascicallreference
		children = append(children, enc_ascicallreference...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.AdditionalInfo != nil {
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := ber.CheckEncodedLength(opts, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		if encodeErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", encodeErr_enc_additionalinfo)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", tagErr_enc_additionalinfo)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.AdditionalSubscriptions != nil {
		if (*v.AdditionalSubscriptions).BitLength < 3 || (*v.AdditionalSubscriptions).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "additionalSubscriptions", "SIZE (3..8)", (*v.AdditionalSubscriptions).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalSubscriptions.Bytes, v.AdditionalSubscriptions.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalSubscriptions", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalSubscriptions.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalsubscriptions, encodeErr_enc_additionalsubscriptions := ber.EncodeBitString(v.AdditionalSubscriptions.Bytes, (8-(v.AdditionalSubscriptions.BitLength%8))%8)
		if encodeErr_enc_additionalsubscriptions != nil {
			return nil, fmt.Errorf("encoding additionalSubscriptions: %w", encodeErr_enc_additionalsubscriptions)
		}
		retagged_enc_additionalsubscriptions, tagErr_enc_additionalsubscriptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalsubscriptions)
		if tagErr_enc_additionalsubscriptions != nil {
			return nil, fmt.Errorf("encoding additionalSubscriptions: %w", tagErr_enc_additionalsubscriptions)
		}
		enc_additionalsubscriptions = retagged_enc_additionalsubscriptions
		children = append(children, enc_additionalsubscriptions...)
	}
	if v.Kc != nil {
		if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(*v.Kc))
		if encodeErr_enc_kc != nil {
			return nil, fmt.Errorf("encoding kc: %w", encodeErr_enc_kc)
		}
		retagged_enc_kc, tagErr_enc_kc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_kc)
		if tagErr_enc_kc != nil {
			return nil, fmt.Errorf("encoding kc: %w", tagErr_enc_kc)
		}
		enc_kc = retagged_enc_kc
		children = append(children, enc_kc...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
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

// MarshalDER encodes SendGroupCallInfoRes to DER format.
func (v *SendGroupCallInfoRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendGroupCallInfoRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.AnchorMSCAddress != nil {
		if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "anchorMSC-Address", "SIZE (1..9)", len(*v.AnchorMSCAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "anchorMSC-Address", "SIZE (1..20)", len(*v.AnchorMSCAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_anchormscaddress, encodeErr_enc_anchormscaddress := ber.EncodeOctetString([]byte(*v.AnchorMSCAddress))
		if encodeErr_enc_anchormscaddress != nil {
			return nil, fmt.Errorf("encoding anchorMSC-Address: %w", encodeErr_enc_anchormscaddress)
		}
		retagged_enc_anchormscaddress, tagErr_enc_anchormscaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_anchormscaddress)
		if tagErr_enc_anchormscaddress != nil {
			return nil, fmt.Errorf("encoding anchorMSC-Address: %w", tagErr_enc_anchormscaddress)
		}
		enc_anchormscaddress = retagged_enc_anchormscaddress
		children = append(children, enc_anchormscaddress...)
	}
	if v.AsciCallReference != nil {
		if len(*v.AsciCallReference) < 1 || len(*v.AsciCallReference) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "asciCallReference", "SIZE (1..8)", len(*v.AsciCallReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ascicallreference, encodeErr_enc_ascicallreference := ber.EncodeOctetString([]byte(*v.AsciCallReference))
		if encodeErr_enc_ascicallreference != nil {
			return nil, fmt.Errorf("encoding asciCallReference: %w", encodeErr_enc_ascicallreference)
		}
		retagged_enc_ascicallreference, tagErr_enc_ascicallreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ascicallreference)
		if tagErr_enc_ascicallreference != nil {
			return nil, fmt.Errorf("encoding asciCallReference: %w", tagErr_enc_ascicallreference)
		}
		enc_ascicallreference = retagged_enc_ascicallreference
		children = append(children, enc_ascicallreference...)
	}
	if v.Imsi != nil {
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.AdditionalInfo != nil {
		if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
			if constraintErr := ber.CheckEncodedLength(nil, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.AdditionalInfo.Bytes, v.AdditionalInfo.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalInfo", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalinfo, encodeErr_enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		if encodeErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", encodeErr_enc_additionalinfo)
		}
		retagged_enc_additionalinfo, tagErr_enc_additionalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_additionalinfo)
		if tagErr_enc_additionalinfo != nil {
			return nil, fmt.Errorf("encoding additionalInfo: %w", tagErr_enc_additionalinfo)
		}
		enc_additionalinfo = retagged_enc_additionalinfo
		children = append(children, enc_additionalinfo...)
	}
	if v.AdditionalSubscriptions != nil {
		if (*v.AdditionalSubscriptions).BitLength < 3 || (*v.AdditionalSubscriptions).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "additionalSubscriptions", "SIZE (3..8)", (*v.AdditionalSubscriptions).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.AdditionalSubscriptions.Bytes, v.AdditionalSubscriptions.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalSubscriptions", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.AdditionalSubscriptions.Bytes, v.AdditionalSubscriptions.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "additionalSubscriptions", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:526
		if v.AdditionalSubscriptions.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_additionalsubscriptions, encodeErr_enc_additionalsubscriptions := ber.EncodeDERNamedBitString(v.AdditionalSubscriptions.Bytes, v.AdditionalSubscriptions.BitLength)
		if encodeErr_enc_additionalsubscriptions != nil {
			return nil, fmt.Errorf("encoding additionalSubscriptions: %w", encodeErr_enc_additionalsubscriptions)
		}
		retagged_enc_additionalsubscriptions, tagErr_enc_additionalsubscriptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_additionalsubscriptions)
		if tagErr_enc_additionalsubscriptions != nil {
			return nil, fmt.Errorf("encoding additionalSubscriptions: %w", tagErr_enc_additionalsubscriptions)
		}
		enc_additionalsubscriptions = retagged_enc_additionalsubscriptions
		children = append(children, enc_additionalsubscriptions...)
	}
	if v.Kc != nil {
		if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(*v.Kc))
		if encodeErr_enc_kc != nil {
			return nil, fmt.Errorf("encoding kc: %w", encodeErr_enc_kc)
		}
		retagged_enc_kc, tagErr_enc_kc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_kc)
		if tagErr_enc_kc != nil {
			return nil, fmt.Errorf("encoding kc: %w", tagErr_enc_kc)
		}
		enc_kc = retagged_enc_kc
		children = append(children, enc_kc...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", tagErr_enc_extensioncontainer)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
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
		return nil, fmt.Errorf("encoding SendGroupCallInfoRes as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SendGroupCallInfoRes from BER/DER format.
func (v *SendGroupCallInfoRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SendGroupCallInfoRes destination is nil", ber.ErrInvalidValue)
	}
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SendGroupCallInfoRes{}
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
		return fmt.Errorf("decoding SendGroupCallInfoRes SEQUENCE: %w", err)
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
				decodedTag_anchormscaddress, n_anchormscaddress, rawVal_anchormscaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding anchorMSC-Address: %w", err)
				}
				if decodedTag_anchormscaddress.Class != tag.ClassContextSpecific || decodedTag_anchormscaddress.Number != 0 {
					return fmt.Errorf("decoding anchorMSC-Address: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_anchormscaddress)
				}
				decVal_anchormscaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_anchormscaddress.Constructed, rawVal_anchormscaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding anchorMSC-Address: %w", octetErr)
				}
				tmp_anchormscaddress := ISDNAddressString(decVal_anchormscaddress)
				v.AnchorMSCAddress = &tmp_anchormscaddress
				if offset < 0 || offset >
					len(content) || n_anchormscaddress < 0 || n_anchormscaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_anchormscaddress
				if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "anchorMSC-Address", "SIZE (1..9)", len(*v.AnchorMSCAddress)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.AnchorMSCAddress) < 1 || len(*v.AnchorMSCAddress) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "anchorMSC-Address", "SIZE (1..20)", len(*v.AnchorMSCAddress)); constraintErr != nil {
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
				decodedTag_ascicallreference, n_ascicallreference, rawVal_ascicallreference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding asciCallReference: %w", err)
				}
				if decodedTag_ascicallreference.Class != tag.ClassContextSpecific || decodedTag_ascicallreference.Number != 1 {
					return fmt.Errorf("decoding asciCallReference: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ascicallreference)
				}
				decVal_ascicallreference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ascicallreference.Constructed, rawVal_ascicallreference, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding asciCallReference: %w", octetErr)
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
					if constraintErr := ber.CheckDecodedLength(opts, "asciCallReference", "SIZE (1..8)", len(*v.AsciCallReference)); constraintErr != nil {
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
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 2 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding imsi: %w", octetErr)
				}
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset < 0 || offset >
					len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
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
				decodedTag_additionalinfo, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding additionalInfo: %w", err)
				}
				if decodedTag_additionalinfo.Class != tag.ClassContextSpecific || decodedTag_additionalinfo.Number != 3 {
					return fmt.Errorf("decoding additionalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalinfo)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalinfo.Constructed, rawVal_additionalinfo, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsErr)
				}
				bsBitLength_additionalinfo, bsLenErr_additionalinfo := ber.BitStringBitLength(len(bsBytes_additionalinfo), bsUnused_additionalinfo)
				if bsLenErr_additionalinfo != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsLenErr_additionalinfo)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: bsBitLength_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				if offset < 0 || offset >
					len(content) || n_additionalinfo < 0 || n_additionalinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_additionalinfo
				if (*v.AdditionalInfo).BitLength < 1 || (*v.AdditionalInfo).BitLength > 136 {
					if constraintErr := ber.CheckDecodedLength(opts, "additionalInfo", "SIZE (1..136)", (*v.AdditionalInfo).BitLength); constraintErr != nil {
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
				decodedTag_additionalsubscriptions, n_additionalsubscriptions, rawVal_additionalsubscriptions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding additionalSubscriptions: %w", err)
				}
				if decodedTag_additionalsubscriptions.Class != tag.ClassContextSpecific || decodedTag_additionalsubscriptions.Number != 4 {
					return fmt.Errorf("decoding additionalSubscriptions: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_additionalsubscriptions)
				}
				bsBytes_additionalsubscriptions, bsUnused_additionalsubscriptions, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_additionalsubscriptions.Constructed, rawVal_additionalsubscriptions, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalSubscriptions: %w", bsErr)
				}
				bsBitLength_additionalsubscriptions, bsLenErr_additionalsubscriptions := ber.BitStringBitLength(len(bsBytes_additionalsubscriptions), bsUnused_additionalsubscriptions)
				if bsLenErr_additionalsubscriptions != nil {
					return fmt.Errorf("decoding additionalSubscriptions: %w", bsLenErr_additionalsubscriptions)
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
					if constraintErr := ber.CheckDecodedLength(opts, "additionalSubscriptions", "SIZE (3..8)", (*v.AdditionalSubscriptions).BitLength); constraintErr != nil {
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
				decodedTag_kc, n_kc, rawVal_kc, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding kc: %w", err)
				}
				if decodedTag_kc.Class != tag.ClassContextSpecific || decodedTag_kc.Number != 5 {
					return fmt.Errorf("decoding kc: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_kc)
				}
				decVal_kc, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_kc.Constructed, rawVal_kc, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding kc: %w", octetErr)
				}
				tmp_kc := Kc(decVal_kc)
				v.Kc = &tmp_kc
				if offset < 0 || offset >
					len(content) || n_kc < 0 || n_kc > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_kc
				if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
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
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 6 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				if reconstructionErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", reconstructionErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
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
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallInfoRes", Cause: extErr_}
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
