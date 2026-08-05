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
}

// GRRequestedInfo represents the ASN.1 ENUMERATED type GRRequestedInfo.
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
}

// MarshalBER encodes PrepareGroupCallArg to BER format.
func (v *PrepareGroupCallArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_teleservice := ber.EncodeOctetString([]byte(v.Teleservice))
	children = append(children, enc_teleservice...)
	enc_ascicallreference := ber.EncodeOctetString([]byte(v.AsciCallReference))
	children = append(children, enc_ascicallreference...)
	enc_codecinfo := ber.EncodeOctetString([]byte(v.CodecInfo))
	children = append(children, enc_codecinfo...)
	enc_cipheringalgorithm := ber.EncodeOctetString([]byte(v.CipheringAlgorithm))
	children = append(children, enc_cipheringalgorithm...)
	if v.GroupKeyNumberVkId != nil {
		enc_groupkeynumbervkid := ber.EncodeInteger(int64(*v.GroupKeyNumberVkId))
		enc_groupkeynumbervkid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_groupkeynumbervkid)
		children = append(children, enc_groupkeynumbervkid...)
	}
	if v.GroupKey != nil {
		enc_groupkey := ber.EncodeOctetString([]byte(*v.GroupKey))
		enc_groupkey = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_groupkey)
		children = append(children, enc_groupkey...)
	}
	if v.Priority != nil {
		enc_priority := ber.EncodeInteger(int64(*v.Priority))
		enc_priority = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_priority)
		children = append(children, enc_priority...)
	}
	if v.UplinkFree != nil {
		enc_uplinkfree := ber.EncodeNull()
		enc_uplinkfree = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_uplinkfree)
		children = append(children, enc_uplinkfree...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.Vstk != nil {
		enc_vstk := ber.EncodeOctetString([]byte(*v.Vstk))
		enc_vstk = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_vstk)
		children = append(children, enc_vstk...)
	}
	if v.VstkRand != nil {
		enc_vstkrand := ber.EncodeOctetString([]byte(*v.VstkRand))
		enc_vstkrand = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_vstkrand)
		children = append(children, enc_vstkrand...)
	}
	if v.TalkerChannelParameter != nil {
		enc_talkerchannelparameter := ber.EncodeNull()
		enc_talkerchannelparameter = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_talkerchannelparameter)
		children = append(children, enc_talkerchannelparameter...)
	}
	if v.UplinkReplyIndicator != nil {
		enc_uplinkreplyindicator := ber.EncodeNull()
		enc_uplinkreplyindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_uplinkreplyindicator)
		children = append(children, enc_uplinkreplyindicator...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PrepareGroupCallArg to DER format.
func (v *PrepareGroupCallArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PrepareGroupCallArg from BER/DER format.
func (v *PrepareGroupCallArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	val_teleservice, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding teleservice: %w", err)
	}
	v.Teleservice = ExtTeleserviceCode(val_teleservice)
	offset += n
	// Decode asciCallReference
	if offset >= len(content) {
		return fmt.Errorf("missing required field asciCallReference")
	}
	val_ascicallreference, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding asciCallReference: %w", err)
	}
	v.AsciCallReference = ASCICallReference(val_ascicallreference)
	offset += n
	// Decode codec-Info
	if offset >= len(content) {
		return fmt.Errorf("missing required field codec-Info")
	}
	val_codecinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding codec-Info: %w", err)
	}
	v.CodecInfo = CODECInfo(val_codecinfo)
	offset += n
	// Decode cipheringAlgorithm
	if offset >= len(content) {
		return fmt.Errorf("missing required field cipheringAlgorithm")
	}
	val_cipheringalgorithm, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding cipheringAlgorithm: %w", err)
	}
	v.CipheringAlgorithm = CipheringAlgorithm(val_cipheringalgorithm)
	offset += n
	// Decode groupKeyNumber-Vk-Id
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_groupkeynumbervkid, rawVal_groupkeynumbervkid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding groupKeyNumber-Vk-Id: %w", err)
				}
				decVal_groupkeynumbervkid, intErr := ber.DecodeIntegerValue(rawVal_groupkeynumbervkid)
				if intErr != nil {
					return fmt.Errorf("decoding groupKeyNumber-Vk-Id: %w", intErr)
				}
				tmp_groupkeynumbervkid := GroupKeyNumber(decVal_groupkeynumbervkid)
				v.GroupKeyNumberVkId = &tmp_groupkeynumbervkid
				offset += n_groupkeynumbervkid
			}
		}
	}
	// Decode groupKey
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_groupkey, rawVal_groupkey, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding groupKey: %w", err)
				}
				tmp_groupkey := Kc(rawVal_groupkey)
				v.GroupKey = &tmp_groupkey
				offset += n_groupkey
			}
		}
	}
	// Decode priority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_priority, rawVal_priority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding priority: %w", err)
				}
				decVal_priority, intErr := ber.DecodeIntegerValue(rawVal_priority)
				if intErr != nil {
					return fmt.Errorf("decoding priority: %w", intErr)
				}
				tmp_priority := EMLPPPriority(decVal_priority)
				v.Priority = &tmp_priority
				offset += n_priority
			}
		}
	}
	// Decode uplinkFree
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_uplinkfree, rawVal_uplinkfree, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uplinkFree: %w", err)
				}
				_ = rawVal_uplinkfree
				v.UplinkFree = &struct{}{}
				offset += n_uplinkfree
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode vstk
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_vstk, rawVal_vstk, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding vstk: %w", err)
				}
				tmp_vstk := VSTK(rawVal_vstk)
				v.Vstk = &tmp_vstk
				offset += n_vstk
			}
		}
	}
	// Decode vstk-rand
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_vstkrand, rawVal_vstkrand, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding vstk-rand: %w", err)
				}
				tmp_vstkrand := VSTKRAND(rawVal_vstkrand)
				v.VstkRand = &tmp_vstkrand
				offset += n_vstkrand
			}
		}
	}
	// Decode talkerChannelParameter
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_talkerchannelparameter, rawVal_talkerchannelparameter, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding talkerChannelParameter: %w", err)
				}
				_ = rawVal_talkerchannelparameter
				v.TalkerChannelParameter = &struct{}{}
				offset += n_talkerchannelparameter
			}
		}
	}
	// Decode uplinkReplyIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_uplinkreplyindicator, rawVal_uplinkreplyindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uplinkReplyIndicator: %w", err)
				}
				_ = rawVal_uplinkreplyindicator
				v.UplinkReplyIndicator = &struct{}{}
				offset += n_uplinkreplyindicator
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareGroupCallArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PrepareGroupCallRes to BER format.
func (v *PrepareGroupCallRes) MarshalBER() ([]byte, error) {
	var children []byte
	enc_groupcallnumber := ber.EncodeOctetString([]byte(v.GroupCallNumber))
	children = append(children, enc_groupcallnumber...)
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes PrepareGroupCallRes to DER format.
func (v *PrepareGroupCallRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PrepareGroupCallRes from BER/DER format.
func (v *PrepareGroupCallRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	val_groupcallnumber, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding groupCallNumber: %w", err)
	}
	v.GroupCallNumber = ISDNAddressString(val_groupcallnumber)
	offset += n
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrepareGroupCallRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SendGroupCallEndSignalArg to BER format.
func (v *SendGroupCallEndSignalArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		children = append(children, enc_imsi...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.TalkerPriority != nil {
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		enc_talkerpriority = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_talkerpriority)
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		enc_additionalinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_additionalinfo)
		children = append(children, enc_additionalinfo...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SendGroupCallEndSignalArg to DER format.
func (v *SendGroupCallEndSignalArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SendGroupCallEndSignalArg from BER/DER format.
func (v *SendGroupCallEndSignalArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				val_imsi, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI(val_imsi)
				v.Imsi = &tmp_imsi
				offset += n
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode talkerPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding talkerPriority: %w", err)
				}
				decVal_talkerpriority, intErr := ber.DecodeIntegerValue(rawVal_talkerpriority)
				if intErr != nil {
					return fmt.Errorf("decoding talkerPriority: %w", intErr)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				offset += n_talkerpriority
			}
		}
	}
	// Decode additionalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalInfo: %w", err)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeBitStringValue(rawVal_additionalinfo)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsErr)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: len(bsBytes_additionalinfo)*8 - bsUnused_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				offset += n_additionalinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallEndSignalArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SendGroupCallEndSignalRes to BER format.
func (v *SendGroupCallEndSignalRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SendGroupCallEndSignalRes to DER format.
func (v *SendGroupCallEndSignalRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SendGroupCallEndSignalRes from BER/DER format.
func (v *SendGroupCallEndSignalRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallEndSignalRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ForwardGroupCallSignallingArg to BER format.
func (v *ForwardGroupCallSignallingArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		children = append(children, enc_imsi...)
	}
	if v.UplinkRequestAck != nil {
		enc_uplinkrequestack := ber.EncodeNull()
		enc_uplinkrequestack = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_uplinkrequestack)
		children = append(children, enc_uplinkrequestack...)
	}
	if v.UplinkReleaseIndication != nil {
		enc_uplinkreleaseindication := ber.EncodeNull()
		enc_uplinkreleaseindication = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_uplinkreleaseindication)
		children = append(children, enc_uplinkreleaseindication...)
	}
	if v.UplinkRejectCommand != nil {
		enc_uplinkrejectcommand := ber.EncodeNull()
		enc_uplinkrejectcommand = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_uplinkrejectcommand)
		children = append(children, enc_uplinkrejectcommand...)
	}
	if v.UplinkSeizedCommand != nil {
		enc_uplinkseizedcommand := ber.EncodeNull()
		enc_uplinkseizedcommand = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_uplinkseizedcommand)
		children = append(children, enc_uplinkseizedcommand...)
	}
	if v.UplinkReleaseCommand != nil {
		enc_uplinkreleasecommand := ber.EncodeNull()
		enc_uplinkreleasecommand = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_uplinkreleasecommand)
		children = append(children, enc_uplinkreleasecommand...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.StateAttributes != nil {
		enc_stateattributes, err := v.StateAttributes.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding stateAttributes: %w", err)
		}
		enc_stateattributes = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_stateattributes)
		children = append(children, enc_stateattributes...)
	}
	if v.TalkerPriority != nil {
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		enc_talkerpriority = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_talkerpriority)
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		enc_additionalinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_additionalinfo)
		children = append(children, enc_additionalinfo...)
	}
	if v.EmergencyModeResetCommandFlag != nil {
		enc_emergencymoderesetcommandflag := ber.EncodeNull()
		enc_emergencymoderesetcommandflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_emergencymoderesetcommandflag)
		children = append(children, enc_emergencymoderesetcommandflag...)
	}
	if v.SmRPUI != nil {
		enc_smrpui := ber.EncodeOctetString([]byte(*v.SmRPUI))
		enc_smrpui = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_smrpui)
		children = append(children, enc_smrpui...)
	}
	if v.AnAPDU != nil {
		enc_anapdu, err := v.AnAPDU.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding an-APDU: %w", err)
		}
		enc_anapdu = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_anapdu)
		children = append(children, enc_anapdu...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ForwardGroupCallSignallingArg to DER format.
func (v *ForwardGroupCallSignallingArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ForwardGroupCallSignallingArg from BER/DER format.
func (v *ForwardGroupCallSignallingArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				val_imsi, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI(val_imsi)
				v.Imsi = &tmp_imsi
				offset += n
			}
		}
	}
	// Decode uplinkRequestAck
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_uplinkrequestack, rawVal_uplinkrequestack, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uplinkRequestAck: %w", err)
				}
				_ = rawVal_uplinkrequestack
				v.UplinkRequestAck = &struct{}{}
				offset += n_uplinkrequestack
			}
		}
	}
	// Decode uplinkReleaseIndication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_uplinkreleaseindication, rawVal_uplinkreleaseindication, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uplinkReleaseIndication: %w", err)
				}
				_ = rawVal_uplinkreleaseindication
				v.UplinkReleaseIndication = &struct{}{}
				offset += n_uplinkreleaseindication
			}
		}
	}
	// Decode uplinkRejectCommand
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_uplinkrejectcommand, rawVal_uplinkrejectcommand, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uplinkRejectCommand: %w", err)
				}
				_ = rawVal_uplinkrejectcommand
				v.UplinkRejectCommand = &struct{}{}
				offset += n_uplinkrejectcommand
			}
		}
	}
	// Decode uplinkSeizedCommand
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_uplinkseizedcommand, rawVal_uplinkseizedcommand, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uplinkSeizedCommand: %w", err)
				}
				_ = rawVal_uplinkseizedcommand
				v.UplinkSeizedCommand = &struct{}{}
				offset += n_uplinkseizedcommand
			}
		}
	}
	// Decode uplinkReleaseCommand
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_uplinkreleasecommand, rawVal_uplinkreleasecommand, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uplinkReleaseCommand: %w", err)
				}
				_ = rawVal_uplinkreleasecommand
				v.UplinkReleaseCommand = &struct{}{}
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
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode stateAttributes
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_stateattributes, rawVal_stateattributes, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding stateAttributes: %w", err)
				}
				reconstructed_stateattributes := ber.EncodeSequence(rawVal_stateattributes)
				var dec_stateattributes StateAttributes
				if unmErr := dec_stateattributes.UnmarshalBER(reconstructed_stateattributes); unmErr != nil {
					return fmt.Errorf("decoding stateAttributes: %w", unmErr)
				}
				v.StateAttributes = &dec_stateattributes
				offset += n_stateattributes
			}
		}
	}
	// Decode talkerPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding talkerPriority: %w", err)
				}
				decVal_talkerpriority, intErr := ber.DecodeIntegerValue(rawVal_talkerpriority)
				if intErr != nil {
					return fmt.Errorf("decoding talkerPriority: %w", intErr)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				offset += n_talkerpriority
			}
		}
	}
	// Decode additionalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalInfo: %w", err)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeBitStringValue(rawVal_additionalinfo)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsErr)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: len(bsBytes_additionalinfo)*8 - bsUnused_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				offset += n_additionalinfo
			}
		}
	}
	// Decode emergencyModeResetCommandFlag
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_emergencymoderesetcommandflag, rawVal_emergencymoderesetcommandflag, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding emergencyModeResetCommandFlag: %w", err)
				}
				_ = rawVal_emergencymoderesetcommandflag
				v.EmergencyModeResetCommandFlag = &struct{}{}
				offset += n_emergencymoderesetcommandflag
			}
		}
	}
	// Decode sm-RP-UI
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				_, n_smrpui, rawVal_smrpui, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sm-RP-UI: %w", err)
				}
				tmp_smrpui := SignalInfo(rawVal_smrpui)
				v.SmRPUI = &tmp_smrpui
				offset += n_smrpui
			}
		}
	}
	// Decode an-APDU
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				_, n_anapdu, rawVal_anapdu, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding an-APDU: %w", err)
				}
				reconstructed_anapdu := ber.EncodeSequence(rawVal_anapdu)
				var dec_anapdu AccessNetworkSignalInfo
				if unmErr := dec_anapdu.UnmarshalBER(reconstructed_anapdu); unmErr != nil {
					return fmt.Errorf("decoding an-APDU: %w", unmErr)
				}
				v.AnAPDU = &dec_anapdu
				offset += n_anapdu
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardGroupCallSignallingArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ProcessGroupCallSignallingArg to BER format.
func (v *ProcessGroupCallSignallingArg) MarshalBER() ([]byte, error) {
	var children []byte
	if v.UplinkRequest != nil {
		enc_uplinkrequest := ber.EncodeNull()
		enc_uplinkrequest = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_uplinkrequest)
		children = append(children, enc_uplinkrequest...)
	}
	if v.UplinkReleaseIndication != nil {
		enc_uplinkreleaseindication := ber.EncodeNull()
		enc_uplinkreleaseindication = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_uplinkreleaseindication)
		children = append(children, enc_uplinkreleaseindication...)
	}
	if v.ReleaseGroupCall != nil {
		enc_releasegroupcall := ber.EncodeNull()
		enc_releasegroupcall = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_releasegroupcall)
		children = append(children, enc_releasegroupcall...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		children = append(children, enc_extensioncontainer...)
	}
	if v.TalkerPriority != nil {
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		enc_talkerpriority = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_talkerpriority)
		children = append(children, enc_talkerpriority...)
	}
	if v.AdditionalInfo != nil {
		enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		enc_additionalinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_additionalinfo)
		children = append(children, enc_additionalinfo...)
	}
	if v.EmergencyModeResetCommandFlag != nil {
		enc_emergencymoderesetcommandflag := ber.EncodeNull()
		enc_emergencymoderesetcommandflag = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_emergencymoderesetcommandflag)
		children = append(children, enc_emergencymoderesetcommandflag...)
	}
	if v.AnAPDU != nil {
		enc_anapdu, err := v.AnAPDU.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding an-APDU: %w", err)
		}
		enc_anapdu = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_anapdu)
		children = append(children, enc_anapdu...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes ProcessGroupCallSignallingArg to DER format.
func (v *ProcessGroupCallSignallingArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ProcessGroupCallSignallingArg from BER/DER format.
func (v *ProcessGroupCallSignallingArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				_, n_uplinkrequest, rawVal_uplinkrequest, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uplinkRequest: %w", err)
				}
				_ = rawVal_uplinkrequest
				v.UplinkRequest = &struct{}{}
				offset += n_uplinkrequest
			}
		}
	}
	// Decode uplinkReleaseIndication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_uplinkreleaseindication, rawVal_uplinkreleaseindication, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uplinkReleaseIndication: %w", err)
				}
				_ = rawVal_uplinkreleaseindication
				v.UplinkReleaseIndication = &struct{}{}
				offset += n_uplinkreleaseindication
			}
		}
	}
	// Decode releaseGroupCall
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_releasegroupcall, rawVal_releasegroupcall, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding releaseGroupCall: %w", err)
				}
				_ = rawVal_releasegroupcall
				v.ReleaseGroupCall = &struct{}{}
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
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset : offset+n_extensioncontainer]); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode talkerPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding talkerPriority: %w", err)
				}
				decVal_talkerpriority, intErr := ber.DecodeIntegerValue(rawVal_talkerpriority)
				if intErr != nil {
					return fmt.Errorf("decoding talkerPriority: %w", intErr)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				offset += n_talkerpriority
			}
		}
	}
	// Decode additionalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalInfo: %w", err)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeBitStringValue(rawVal_additionalinfo)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsErr)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: len(bsBytes_additionalinfo)*8 - bsUnused_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				offset += n_additionalinfo
			}
		}
	}
	// Decode emergencyModeResetCommandFlag
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_emergencymoderesetcommandflag, rawVal_emergencymoderesetcommandflag, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding emergencyModeResetCommandFlag: %w", err)
				}
				_ = rawVal_emergencymoderesetcommandflag
				v.EmergencyModeResetCommandFlag = &struct{}{}
				offset += n_emergencymoderesetcommandflag
			}
		}
	}
	// Decode an-APDU
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_anapdu, rawVal_anapdu, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding an-APDU: %w", err)
				}
				reconstructed_anapdu := ber.EncodeSequence(rawVal_anapdu)
				var dec_anapdu AccessNetworkSignalInfo
				if unmErr := dec_anapdu.UnmarshalBER(reconstructed_anapdu); unmErr != nil {
					return fmt.Errorf("decoding an-APDU: %w", unmErr)
				}
				v.AnAPDU = &dec_anapdu
				offset += n_anapdu
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProcessGroupCallSignallingArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes StateAttributes to BER format.
func (v *StateAttributes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.DownlinkAttached != nil {
		enc_downlinkattached := ber.EncodeNull()
		enc_downlinkattached = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_downlinkattached)
		children = append(children, enc_downlinkattached...)
	}
	if v.UplinkAttached != nil {
		enc_uplinkattached := ber.EncodeNull()
		enc_uplinkattached = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_uplinkattached)
		children = append(children, enc_uplinkattached...)
	}
	if v.DualCommunication != nil {
		enc_dualcommunication := ber.EncodeNull()
		enc_dualcommunication = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_dualcommunication)
		children = append(children, enc_dualcommunication...)
	}
	if v.CallOriginator != nil {
		enc_calloriginator := ber.EncodeNull()
		enc_calloriginator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_calloriginator)
		children = append(children, enc_calloriginator...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes StateAttributes to DER format.
func (v *StateAttributes) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes StateAttributes from BER/DER format.
func (v *StateAttributes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				_, n_downlinkattached, rawVal_downlinkattached, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding downlinkAttached: %w", err)
				}
				_ = rawVal_downlinkattached
				v.DownlinkAttached = &struct{}{}
				offset += n_downlinkattached
			}
		}
	}
	// Decode uplinkAttached
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_uplinkattached, rawVal_uplinkattached, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding uplinkAttached: %w", err)
				}
				_ = rawVal_uplinkattached
				v.UplinkAttached = &struct{}{}
				offset += n_uplinkattached
			}
		}
	}
	// Decode dualCommunication
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				_, n_dualcommunication, rawVal_dualcommunication, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding dualCommunication: %w", err)
				}
				_ = rawVal_dualcommunication
				v.DualCommunication = &struct{}{}
				offset += n_dualcommunication
			}
		}
	}
	// Decode callOriginator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				_, n_calloriginator, rawVal_calloriginator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding callOriginator: %w", err)
				}
				_ = rawVal_calloriginator
				v.CallOriginator = &struct{}{}
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
func (v *SendGroupCallInfoArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_requestedinfo := ber.EncodeEnumerated(int64(v.RequestedInfo))
	children = append(children, enc_requestedinfo...)
	enc_groupid := ber.EncodeOctetString([]byte(v.GroupId))
	children = append(children, enc_groupid...)
	enc_teleservice := ber.EncodeOctetString([]byte(v.Teleservice))
	children = append(children, enc_teleservice...)
	if v.CellId != nil {
		enc_cellid := ber.EncodeOctetString([]byte(*v.CellId))
		enc_cellid = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_cellid)
		children = append(children, enc_cellid...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	if v.Tmsi != nil {
		enc_tmsi := ber.EncodeOctetString([]byte(*v.Tmsi))
		enc_tmsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_tmsi)
		children = append(children, enc_tmsi...)
	}
	if v.AdditionalInfo != nil {
		enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		enc_additionalinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_additionalinfo)
		children = append(children, enc_additionalinfo...)
	}
	if v.TalkerPriority != nil {
		enc_talkerpriority := ber.EncodeEnumerated(int64(*v.TalkerPriority))
		enc_talkerpriority = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_talkerpriority)
		children = append(children, enc_talkerpriority...)
	}
	if v.Cksn != nil {
		enc_cksn := ber.EncodeOctetString([]byte(*v.Cksn))
		enc_cksn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_cksn)
		children = append(children, enc_cksn...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SendGroupCallInfoArg to DER format.
func (v *SendGroupCallInfoArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SendGroupCallInfoArg from BER/DER format.
func (v *SendGroupCallInfoArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
	val_requestedinfo, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding requestedInfo: %w", err)
	}
	v.RequestedInfo = GRRequestedInfo(val_requestedinfo)
	offset += n
	// Decode groupId
	if offset >= len(content) {
		return fmt.Errorf("missing required field groupId")
	}
	val_groupid, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding groupId: %w", err)
	}
	v.GroupId = LongGroupId(val_groupid)
	offset += n
	// Decode teleservice
	if offset >= len(content) {
		return fmt.Errorf("missing required field teleservice")
	}
	val_teleservice, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding teleservice: %w", err)
	}
	v.Teleservice = ExtTeleserviceCode(val_teleservice)
	offset += n
	// Decode cellId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_cellid, rawVal_cellid, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cellId: %w", err)
				}
				tmp_cellid := GlobalCellId(rawVal_cellid)
				v.CellId = &tmp_cellid
				offset += n_cellid
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode tmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_tmsi, rawVal_tmsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding tmsi: %w", err)
				}
				tmp_tmsi := TMSI(rawVal_tmsi)
				v.Tmsi = &tmp_tmsi
				offset += n_tmsi
			}
		}
	}
	// Decode additionalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalInfo: %w", err)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeBitStringValue(rawVal_additionalinfo)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsErr)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: len(bsBytes_additionalinfo)*8 - bsUnused_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				offset += n_additionalinfo
			}
		}
	}
	// Decode talkerPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_talkerpriority, rawVal_talkerpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding talkerPriority: %w", err)
				}
				decVal_talkerpriority, intErr := ber.DecodeIntegerValue(rawVal_talkerpriority)
				if intErr != nil {
					return fmt.Errorf("decoding talkerPriority: %w", intErr)
				}
				tmp_talkerpriority := TalkerPriority(decVal_talkerpriority)
				v.TalkerPriority = &tmp_talkerpriority
				offset += n_talkerpriority
			}
		}
	}
	// Decode cksn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_cksn, rawVal_cksn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cksn: %w", err)
				}
				tmp_cksn := Cksn(rawVal_cksn)
				v.Cksn = &tmp_cksn
				offset += n_cksn
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallInfoArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SendGroupCallInfoRes to BER format.
func (v *SendGroupCallInfoRes) MarshalBER() ([]byte, error) {
	var children []byte
	if v.AnchorMSCAddress != nil {
		enc_anchormscaddress := ber.EncodeOctetString([]byte(*v.AnchorMSCAddress))
		enc_anchormscaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_anchormscaddress)
		children = append(children, enc_anchormscaddress...)
	}
	if v.AsciCallReference != nil {
		enc_ascicallreference := ber.EncodeOctetString([]byte(*v.AsciCallReference))
		enc_ascicallreference = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_ascicallreference)
		children = append(children, enc_ascicallreference...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	if v.AdditionalInfo != nil {
		enc_additionalinfo := ber.EncodeBitString(v.AdditionalInfo.Bytes, (8-(v.AdditionalInfo.BitLength%8))%8)
		enc_additionalinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_additionalinfo)
		children = append(children, enc_additionalinfo...)
	}
	if v.AdditionalSubscriptions != nil {
		enc_additionalsubscriptions := ber.EncodeBitString(v.AdditionalSubscriptions.Bytes, (8-(v.AdditionalSubscriptions.BitLength%8))%8)
		enc_additionalsubscriptions = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_additionalsubscriptions)
		children = append(children, enc_additionalsubscriptions...)
	}
	if v.Kc != nil {
		enc_kc := ber.EncodeOctetString([]byte(*v.Kc))
		enc_kc = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_kc)
		children = append(children, enc_kc...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		_, n, _, extErr := ber.DecodeTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SendGroupCallInfoRes to DER format.
func (v *SendGroupCallInfoRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SendGroupCallInfoRes from BER/DER format.
func (v *SendGroupCallInfoRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
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
				_, n_anchormscaddress, rawVal_anchormscaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding anchorMSC-Address: %w", err)
				}
				tmp_anchormscaddress := ISDNAddressString(rawVal_anchormscaddress)
				v.AnchorMSCAddress = &tmp_anchormscaddress
				offset += n_anchormscaddress
			}
		}
	}
	// Decode asciCallReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_ascicallreference, rawVal_ascicallreference, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding asciCallReference: %w", err)
				}
				tmp_ascicallreference := ASCICallReference(rawVal_ascicallreference)
				v.AsciCallReference = &tmp_ascicallreference
				offset += n_ascicallreference
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode additionalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_additionalinfo, rawVal_additionalinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalInfo: %w", err)
				}
				bsBytes_additionalinfo, bsUnused_additionalinfo, bsErr := ber.DecodeBitStringValue(rawVal_additionalinfo)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalInfo: %w", bsErr)
				}
				tmp_additionalinfo := runtime.BitString{Bytes: bsBytes_additionalinfo, BitLength: len(bsBytes_additionalinfo)*8 - bsUnused_additionalinfo}
				v.AdditionalInfo = &tmp_additionalinfo
				offset += n_additionalinfo
			}
		}
	}
	// Decode additionalSubscriptions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				_, n_additionalsubscriptions, rawVal_additionalsubscriptions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding additionalSubscriptions: %w", err)
				}
				bsBytes_additionalsubscriptions, bsUnused_additionalsubscriptions, bsErr := ber.DecodeBitStringValue(rawVal_additionalsubscriptions)
				if bsErr != nil {
					return fmt.Errorf("decoding additionalSubscriptions: %w", bsErr)
				}
				tmp_additionalsubscriptions := runtime.BitString{Bytes: bsBytes_additionalsubscriptions, BitLength: len(bsBytes_additionalsubscriptions)*8 - bsUnused_additionalsubscriptions}
				v.AdditionalSubscriptions = &tmp_additionalsubscriptions
				offset += n_additionalsubscriptions
			}
		}
	}
	// Decode kc
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_kc, rawVal_kc, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding kc: %w", err)
				}
				tmp_kc := Kc(rawVal_kc)
				v.Kc = &tmp_kc
				offset += n_kc
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendGroupCallInfoRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
