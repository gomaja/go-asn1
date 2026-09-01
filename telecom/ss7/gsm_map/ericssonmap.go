// Code generated from ASN.1 module "EricssonMAP". DO NOT EDIT.

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

// EnhancedCheckIMEIArg represents the ASN.1 type EnhancedCheckIMEIArg (SEQUENCE).
type EnhancedCheckIMEIArg struct {
	Imei                   IMEI4                    `asn1:""`
	RequestedEquipmentInfo *RequestedEquipmentInfo4 `asn1:",optional" json:"RequestedEquipmentInfo,omitempty"`
	Imsi                   *IMSI4                   `asn1:"tag:1,private,implicit,optional" json:"Imsi,omitempty"`
	LocationInformation    []byte                   `asn1:"tag:3,private,implicit,optional" json:"LocationInformation,omitempty"`
	ExtensionContainer     *ExtensionContainer4     `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_              int64                    `asn1:"-" json:"-"`
	ExtPresent_            []bool                   `asn1:"-" json:"-"`
	ExtData_               [][]byte                 `asn1:"-" json:"-"`
}

// ExtensionType choice constants.
const (
	ExtensionTypeChoiceIsdArgType    = 1
	ExtensionTypeChoiceIsdResType    = 2
	ExtensionTypeChoiceDsdArgType    = 3
	ExtensionTypeChoiceSriArgType    = 4
	ExtensionTypeChoiceSriResType    = 5
	ExtensionTypeChoicePrnArgType    = 6
	ExtensionTypeChoiceUlArgType     = 7
	ExtensionTypeChoiceRdArgType     = 8
	ExtensionTypeChoiceSaiArgType    = 9
	ExtensionTypeChoiceSaiResType    = 10
	ExtensionTypeChoiceAtiArgType    = 11
	ExtensionTypeChoiceAtiResType    = 12
	ExtensionTypeChoiceExtAtiArgType = 13
)

// ExtensionType represents the ASN.1 CHOICE type ExtensionType.
type ExtensionType struct {
	Choice        int
	IsdArgType    IsdArgType    `json:"IsdArgType,omitempty"`
	IsdResType    IsdResType    `json:"IsdResType,omitempty"`
	DsdArgType    DsdArgType    `json:"DsdArgType,omitempty"`
	SriArgType    SRIArgType    `json:"SriArgType,omitempty"`
	SriResType    SRIResType    `json:"SriResType,omitempty"`
	PrnArgType    PrnArgType    `json:"PrnArgType,omitempty"`
	UlArgType     UlArgType     `json:"UlArgType,omitempty"`
	RdArgType     *RdArgType    `json:"RdArgType,omitempty"`
	SaiArgType    *SaiArgType   `json:"SaiArgType,omitempty"`
	SaiResType    *SaiResType   `json:"SaiResType,omitempty"`
	AtiArgType    *AtiArgType   `json:"AtiArgType,omitempty"`
	AtiResType    *AtiResType   `json:"AtiResType,omitempty"`
	ExtAtiArgType ExtAtiArgType `json:"ExtAtiArgType,omitempty"`
}

// NewExtensionTypeIsdArgType creates a ExtensionType with the isdArgType alternative.
func NewExtensionTypeIsdArgType(v IsdArgType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceIsdArgType,
		IsdArgType: v,
	}
}

// NewExtensionTypeIsdResType creates a ExtensionType with the isdResType alternative.
func NewExtensionTypeIsdResType(v IsdResType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceIsdResType,
		IsdResType: v,
	}
}

// NewExtensionTypeDsdArgType creates a ExtensionType with the dsdArgType alternative.
func NewExtensionTypeDsdArgType(v DsdArgType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceDsdArgType,
		DsdArgType: v,
	}
}

// NewExtensionTypeSriArgType creates a ExtensionType with the sriArgType alternative.
func NewExtensionTypeSriArgType(v SRIArgType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceSriArgType,
		SriArgType: v,
	}
}

// NewExtensionTypeSriResType creates a ExtensionType with the sriResType alternative.
func NewExtensionTypeSriResType(v SRIResType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceSriResType,
		SriResType: v,
	}
}

// NewExtensionTypePrnArgType creates a ExtensionType with the prnArgType alternative.
func NewExtensionTypePrnArgType(v PrnArgType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoicePrnArgType,
		PrnArgType: v,
	}
}

// NewExtensionTypeUlArgType creates a ExtensionType with the ulArgType alternative.
func NewExtensionTypeUlArgType(v UlArgType) ExtensionType {
	return ExtensionType{
		Choice:    ExtensionTypeChoiceUlArgType,
		UlArgType: v,
	}
}

// NewExtensionTypeRdArgType creates a ExtensionType with the rdArgType alternative.
func NewExtensionTypeRdArgType(v RdArgType) ExtensionType {
	return ExtensionType{
		Choice:    ExtensionTypeChoiceRdArgType,
		RdArgType: &v,
	}
}

// NewExtensionTypeSaiArgType creates a ExtensionType with the saiArgType alternative.
func NewExtensionTypeSaiArgType(v SaiArgType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceSaiArgType,
		SaiArgType: &v,
	}
}

// NewExtensionTypeSaiResType creates a ExtensionType with the saiResType alternative.
func NewExtensionTypeSaiResType(v SaiResType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceSaiResType,
		SaiResType: &v,
	}
}

// NewExtensionTypeAtiArgType creates a ExtensionType with the atiArgType alternative.
func NewExtensionTypeAtiArgType(v AtiArgType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceAtiArgType,
		AtiArgType: &v,
	}
}

// NewExtensionTypeAtiResType creates a ExtensionType with the atiResType alternative.
func NewExtensionTypeAtiResType(v AtiResType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceAtiResType,
		AtiResType: &v,
	}
}

// NewExtensionTypeExtAtiArgType creates a ExtensionType with the extAtiArgType alternative.
func NewExtensionTypeExtAtiArgType(v ExtAtiArgType) ExtensionType {
	return ExtensionType{
		Choice:        ExtensionTypeChoiceExtAtiArgType,
		ExtAtiArgType: v,
	}
}

// IsdArgType represents the ASN.1 type IsdArgType (SEQUENCE_OF).
type IsdArgType = []IsdArgData

// IsdArgData represents the ASN.1 type IsdArgData (SEQUENCE).
type IsdArgData struct {
	PrivateFeatureCode *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	PrivateFeatureData *PrivateFeatureData `asn1:",optional" json:"PrivateFeatureData,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// PrivateFeatureData choice constants.
const (
	PrivateFeatureDataChoiceSubscriptionTypeInfo = 1
	PrivateFeatureDataChoiceOickInfo             = 2
)

// PrivateFeatureData represents the ASN.1 CHOICE type PrivateFeatureData.
type PrivateFeatureData struct {
	Choice               int
	SubscriptionTypeInfo *SubscriptionTypeInfo `json:"SubscriptionTypeInfo,omitempty"`
	OickInfo             *OickInfo             `json:"OickInfo,omitempty"`
}

// NewPrivateFeatureDataSubscriptionTypeInfo creates a PrivateFeatureData with the subscriptionTypeInfo alternative.
func NewPrivateFeatureDataSubscriptionTypeInfo(v SubscriptionTypeInfo) PrivateFeatureData {
	return PrivateFeatureData{
		Choice:               PrivateFeatureDataChoiceSubscriptionTypeInfo,
		SubscriptionTypeInfo: &v,
	}
}

// NewPrivateFeatureDataOickInfo creates a PrivateFeatureData with the oickInfo alternative.
func NewPrivateFeatureDataOickInfo(v OickInfo) PrivateFeatureData {
	return PrivateFeatureData{
		Choice:   PrivateFeatureDataChoiceOickInfo,
		OickInfo: &v,
	}
}

// OickInfo represents the ASN.1 type OickInfo (SEQUENCE).
type OickInfo struct {
	SsStatus      ExtSSStatus4  `asn1:""`
	InCategoryKey INCategoryKey `asn1:""`
}

// INCategoryKey represents the ASN.1 type INCategoryKey (OCTET_STRING).
type INCategoryKey = TBCDSTRING4

// SubscriptionTypeInfo represents the ASN.1 type SubscriptionTypeInfo (SEQUENCE).
type SubscriptionTypeInfo struct {
	SubscriptionType SubscriptionType `asn1:""`
}

// SubscriptionType represents the ASN.1 type SubscriptionType (OCTET_STRING).
type SubscriptionType = []byte

// IsdResType represents the ASN.1 type IsdResType (SEQUENCE_OF).
type IsdResType = []IsdResData

// IsdResData represents the ASN.1 type IsdResData (SEQUENCE).
type IsdResData struct {
	SupportedPrivateFeature *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"SupportedPrivateFeature,omitempty"`
	ExtCount_               int64               `asn1:"-" json:"-"`
	ExtPresent_             []bool              `asn1:"-" json:"-"`
	ExtData_                [][]byte            `asn1:"-" json:"-"`
}

// DsdArgType represents the ASN.1 type DsdArgType (SEQUENCE_OF).
type DsdArgType = []DsdArgData

// DsdArgData represents the ASN.1 type DsdArgData (SEQUENCE).
type DsdArgData struct {
	PrivateFeatureWithdraw PrivateFeatureCode `asn1:""`
}

// SRIArgType represents the ASN.1 type SRIArgType (SEQUENCE_OF).
type SRIArgType = []SriArgData

// SriArgData represents the ASN.1 type SriArgData (SEQUENCE).
type SriArgData struct {
	PrivateFeatureCode *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	ExtraNetworkInfo   *ExtraSignalInfo    `asn1:"tag:2,context,implicit,optional" json:"ExtraNetworkInfo,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// SRIResType represents the ASN.1 type SRIResType (SEQUENCE_OF).
type SRIResType = []SriResData

// SriResData represents the ASN.1 type SriResData (SEQUENCE).
type SriResData struct {
	PrivateFeatureCode *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	InCategoryKey      *INCategoryKey      `asn1:"tag:2,context,implicit,optional" json:"InCategoryKey,omitempty"`
	SubscriptionType   *SubscriptionType   `asn1:"tag:5,context,implicit,optional" json:"SubscriptionType,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// PrnArgType represents the ASN.1 type PrnArgType (SEQUENCE_OF).
type PrnArgType = []PrnArgData

// PrnArgData represents the ASN.1 type PrnArgData (SEQUENCE).
type PrnArgData struct {
	PrivateFeatureCode *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	ExtraNetworkInfo   *ExtraSignalInfo    `asn1:"tag:2,context,implicit,optional" json:"ExtraNetworkInfo,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// UlArgType represents the ASN.1 type UlArgType (SEQUENCE_OF).
type UlArgType = []UlArgData

// UlArgData represents the ASN.1 type UlArgData (SEQUENCE).
type UlArgData struct {
	PrivateFeatureCode      *PrivateFeatureCode      `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	PrivateFeatureUlArgData *PrivateFeatureUlArgData `asn1:",optional" json:"PrivateFeatureUlArgData,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
}

// PrivateFeatureUlArgData choice constants.
const (
	PrivateFeatureUlArgDataChoiceAdc = 1
)

// PrivateFeatureUlArgData represents the ASN.1 CHOICE type PrivateFeatureUlArgData.
type PrivateFeatureUlArgData struct {
	Choice int
	Adc    *IMEI4 `json:"Adc,omitempty"`
}

// NewPrivateFeatureUlArgDataAdc creates a PrivateFeatureUlArgData with the adc alternative.
func NewPrivateFeatureUlArgDataAdc(v IMEI4) PrivateFeatureUlArgData {
	return PrivateFeatureUlArgData{
		Choice: PrivateFeatureUlArgDataChoiceAdc,
		Adc:    &v,
	}
}

// ExtraProtocolId represents the ASN.1 INTEGER type ExtraProtocolId with named numbers.
type ExtraProtocolId int64

const (
	ExtraProtocolIdQ763 ExtraProtocolId = 1
)

func (v ExtraProtocolId) String() string {
	switch v {
	case ExtraProtocolIdQ763:
		return "q763"
	default:
		return "unknown"
	}
}

// ExtraSignalInfo represents the ASN.1 type ExtraSignalInfo (SEQUENCE).
type ExtraSignalInfo struct {
	ProtocolId ExtraProtocolId `asn1:""`
	SignalInfo SignalInfo4     `asn1:""`
}

// SaiArgType represents the ASN.1 type SaiArgType (SEQUENCE).
type SaiArgType struct {
	Msisdn                   *struct{} `asn1:"tag:1,context,implicit,optional" json:"Msisdn,omitempty"`
	NoAuthenVectorsRequested *struct{} `asn1:"tag:2,context,implicit,optional" json:"NoAuthenVectorsRequested,omitempty"`
}

// SaiResType represents the ASN.1 type SaiResType (SEQUENCE).
type SaiResType struct {
	MsIsdn *ISDNAddressString4 `asn1:"tag:1,context,implicit,optional" json:"MsIsdn,omitempty"`
}

// AtiArgType represents the ASN.1 type AtiArgType (SEQUENCE).
type AtiArgType struct {
	RequestedInfoType *RequestedInfoType `asn1:"tag:0,context,implicit,optional" json:"RequestedInfoType,omitempty"`
}

// AtiResType represents the ASN.1 type AtiResType (SEQUENCE).
type AtiResType struct {
	ToBeDecided *struct{} `asn1:"tag:1,context,implicit,optional" json:"ToBeDecided,omitempty"`
}

// RdArgType represents the ASN.1 type RdArgType (SEQUENCE).
type RdArgType struct {
	ToBeDecidedOne *struct{} `asn1:"tag:1,context,implicit,optional" json:"ToBeDecidedOne,omitempty"`
}

// RequestedInfoType represents the ASN.1 type RequestedInfoType (SEQUENCE).
type RequestedInfoType struct {
	SgsnNumber *struct{} `asn1:"tag:0,context,implicit,optional" json:"SgsnNumber,omitempty"`
}

// ExtAtiArgType represents the ASN.1 type ExtAtiArgType (SEQUENCE_OF).
type ExtAtiArgType = []AtiArgData

// AtiArgData represents the ASN.1 type AtiArgData (SEQUENCE).
type AtiArgData struct {
	PrivateFeatureCode *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
}

// PrivateFeatureCode represents the ASN.1 type PrivateFeatureCode (OCTET_STRING).
type PrivateFeatureCode = []byte

// MarshalBER encodes EnhancedCheckIMEIArg to BER format.
func (v *EnhancedCheckIMEIArg) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imei := ber.EncodeOctetString([]byte(v.Imei))
	children = append(children, enc_imei...)
	if v.RequestedEquipmentInfo != nil {
		enc_requestedequipmentinfo := ber.EncodeBitString(v.RequestedEquipmentInfo.Bytes, (8-(v.RequestedEquipmentInfo.BitLength%8))%8)
		children = append(children, enc_requestedequipmentinfo...)
	}
	if v.Imsi != nil {
		enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 1, false, enc_imsi)
		children = append(children, enc_imsi...)
	}
	if v.LocationInformation != nil {
		enc_locationinformation := ber.EncodeOctetString(v.LocationInformation)
		enc_locationinformation = ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 3, false, enc_locationinformation)
		children = append(children, enc_locationinformation...)
	}
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

// MarshalDER encodes EnhancedCheckIMEIArg to DER format.
func (v *EnhancedCheckIMEIArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EnhancedCheckIMEIArg from BER/DER format.
func (v *EnhancedCheckIMEIArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EnhancedCheckIMEIArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EnhancedCheckIMEIArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imei
	if offset >= len(content) {
		return fmt.Errorf("missing required field imei")
	}
	val_imei, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imei: %w", err)
	}
	v.Imei = IMEI4(val_imei)
	offset += n
	// Decode requestedEquipmentInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 3 {
				bsBytes_requestedequipmentinfo, bsUnused_requestedequipmentinfo, n, err := ber.DecodeBitString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding requestedEquipmentInfo: %w", err)
				}
				tmp_requestedequipmentinfo := runtime.BitString{Bytes: bsBytes_requestedequipmentinfo, BitLength: len(bsBytes_requestedequipmentinfo)*8 - bsUnused_requestedequipmentinfo}
				v.RequestedEquipmentInfo = &tmp_requestedequipmentinfo
				offset += n
			}
		}
	}
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassPrivate && peekTag.Number == 1 {
				_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				tmp_imsi := IMSI4(rawVal_imsi)
				v.Imsi = &tmp_imsi
				offset += n_imsi
			}
		}
	}
	// Decode locationInformation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassPrivate && peekTag.Number == 3 {
				_, n_locationinformation, rawVal_locationinformation, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding locationInformation: %w", err)
				}
				tmp_locationinformation := rawVal_locationinformation
				v.LocationInformation = tmp_locationinformation
				offset += n_locationinformation
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer4)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer4
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
			return &ber.DecodeError{Offset: offset, TypeName: "EnhancedCheckIMEIArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes ExtensionType to BER format.
func (v *ExtensionType) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case ExtensionTypeChoiceIsdArgType:
		if v.IsdArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: isdArgType is nil")
		}
		enc_0, err := MarshalBERIsdArgType(v.IsdArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding isdArgType: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_0)
		return enc_0, nil
	case ExtensionTypeChoiceIsdResType:
		if v.IsdResType == nil {
			return nil, fmt.Errorf("choice ExtensionType: isdResType is nil")
		}
		enc_1, err := MarshalBERIsdResType(v.IsdResType)
		if err != nil {
			return nil, fmt.Errorf("encoding isdResType: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_1)
		return enc_1, nil
	case ExtensionTypeChoiceDsdArgType:
		if v.DsdArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: dsdArgType is nil")
		}
		enc_2, err := MarshalBERDsdArgType(v.DsdArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding dsdArgType: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	case ExtensionTypeChoiceSriArgType:
		if v.SriArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: sriArgType is nil")
		}
		enc_3, err := MarshalBERSRIArgType(v.SriArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding sriArgType: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_3)
		return enc_3, nil
	case ExtensionTypeChoiceSriResType:
		if v.SriResType == nil {
			return nil, fmt.Errorf("choice ExtensionType: sriResType is nil")
		}
		enc_4, err := MarshalBERSRIResType(v.SriResType)
		if err != nil {
			return nil, fmt.Errorf("encoding sriResType: %w", err)
		}
		enc_4 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, true, enc_4)
		return enc_4, nil
	case ExtensionTypeChoicePrnArgType:
		if v.PrnArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: prnArgType is nil")
		}
		enc_5, err := MarshalBERPrnArgType(v.PrnArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding prnArgType: %w", err)
		}
		enc_5 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, true, enc_5)
		return enc_5, nil
	case ExtensionTypeChoiceUlArgType:
		if v.UlArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: ulArgType is nil")
		}
		enc_6, err := MarshalBERUlArgType(v.UlArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding ulArgType: %w", err)
		}
		enc_6 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_6)
		return enc_6, nil
	case ExtensionTypeChoiceRdArgType:
		if v.RdArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: rdArgType is nil")
		}
		enc_7, err := v.RdArgType.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding rdArgType: %w", err)
		}
		enc_7 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_7)
		return enc_7, nil
	case ExtensionTypeChoiceSaiArgType:
		if v.SaiArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: saiArgType is nil")
		}
		enc_8, err := v.SaiArgType.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding saiArgType: %w", err)
		}
		enc_8 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_8)
		return enc_8, nil
	case ExtensionTypeChoiceSaiResType:
		if v.SaiResType == nil {
			return nil, fmt.Errorf("choice ExtensionType: saiResType is nil")
		}
		enc_9, err := v.SaiResType.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding saiResType: %w", err)
		}
		enc_9 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_9)
		return enc_9, nil
	case ExtensionTypeChoiceAtiArgType:
		if v.AtiArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: atiArgType is nil")
		}
		enc_10, err := v.AtiArgType.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding atiArgType: %w", err)
		}
		enc_10 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, true, enc_10)
		return enc_10, nil
	case ExtensionTypeChoiceAtiResType:
		if v.AtiResType == nil {
			return nil, fmt.Errorf("choice ExtensionType: atiResType is nil")
		}
		enc_11, err := v.AtiResType.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding atiResType: %w", err)
		}
		enc_11 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, true, enc_11)
		return enc_11, nil
	case ExtensionTypeChoiceExtAtiArgType:
		if v.ExtAtiArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: extAtiArgType is nil")
		}
		enc_12, err := MarshalBERExtAtiArgType(v.ExtAtiArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding extAtiArgType: %w", err)
		}
		enc_12 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, true, enc_12)
		return enc_12, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ExtensionType", v.Choice)
	}
}

// MarshalDER encodes ExtensionType to DER format.
func (v *ExtensionType) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case ExtensionTypeChoiceRdArgType:
		if v.RdArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: rdArgType is nil")
		}
		enc_der_7, err := v.RdArgType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding rdArgType: %w", err)
		}
		enc_der_7 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, true, enc_der_7)
		return enc_der_7, nil
	case ExtensionTypeChoiceSaiArgType:
		if v.SaiArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: saiArgType is nil")
		}
		enc_der_8, err := v.SaiArgType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding saiArgType: %w", err)
		}
		enc_der_8 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, true, enc_der_8)
		return enc_der_8, nil
	case ExtensionTypeChoiceSaiResType:
		if v.SaiResType == nil {
			return nil, fmt.Errorf("choice ExtensionType: saiResType is nil")
		}
		enc_der_9, err := v.SaiResType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding saiResType: %w", err)
		}
		enc_der_9 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, true, enc_der_9)
		return enc_der_9, nil
	case ExtensionTypeChoiceAtiArgType:
		if v.AtiArgType == nil {
			return nil, fmt.Errorf("choice ExtensionType: atiArgType is nil")
		}
		enc_der_10, err := v.AtiArgType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding atiArgType: %w", err)
		}
		enc_der_10 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, true, enc_der_10)
		return enc_der_10, nil
	case ExtensionTypeChoiceAtiResType:
		if v.AtiResType == nil {
			return nil, fmt.Errorf("choice ExtensionType: atiResType is nil")
		}
		enc_der_11, err := v.AtiResType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding atiResType: %w", err)
		}
		enc_der_11 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, true, enc_der_11)
		return enc_der_11, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes ExtensionType from BER/DER format.
func (v *ExtensionType) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtensionType CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtensionType: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding ExtensionType CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionType", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = ExtensionTypeChoiceIsdArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding isdArgType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERIsdArgType(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding isdArgType: %w", unmErr)
		}
		v.IsdArgType = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = ExtensionTypeChoiceIsdResType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding isdResType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERIsdResType(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding isdResType: %w", unmErr)
		}
		v.IsdResType = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = ExtensionTypeChoiceDsdArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding dsdArgType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERDsdArgType(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding dsdArgType: %w", unmErr)
		}
		v.DsdArgType = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = ExtensionTypeChoiceSriArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding sriArgType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERSRIArgType(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding sriArgType: %w", unmErr)
		}
		v.SriArgType = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
		v.Choice = ExtensionTypeChoiceSriResType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding sriResType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERSRIResType(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding sriResType: %w", unmErr)
		}
		v.SriResType = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
		v.Choice = ExtensionTypeChoicePrnArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding prnArgType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERPrnArgType(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding prnArgType: %w", unmErr)
		}
		v.PrnArgType = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
		v.Choice = ExtensionTypeChoiceUlArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ulArgType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERUlArgType(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding ulArgType: %w", unmErr)
		}
		v.UlArgType = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
		v.Choice = ExtensionTypeChoiceRdArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding rdArgType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec RdArgType
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding rdArgType: %w", unmErr)
		}
		v.RdArgType = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
		v.Choice = ExtensionTypeChoiceSaiArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding saiArgType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SaiArgType
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding saiArgType: %w", unmErr)
		}
		v.SaiArgType = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
		v.Choice = ExtensionTypeChoiceSaiResType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding saiResType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SaiResType
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding saiResType: %w", unmErr)
		}
		v.SaiResType = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
		v.Choice = ExtensionTypeChoiceAtiArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding atiArgType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AtiArgType
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding atiArgType: %w", unmErr)
		}
		v.AtiArgType = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
		v.Choice = ExtensionTypeChoiceAtiResType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding atiResType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec AtiResType
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding atiResType: %w", unmErr)
		}
		v.AtiResType = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
		v.Choice = ExtensionTypeChoiceExtAtiArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding extAtiArgType: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERExtAtiArgType(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding extAtiArgType: %w", unmErr)
		}
		v.ExtAtiArgType = dec
	} else {
		return fmt.Errorf("unknown tag %s for ExtensionType CHOICE", peekTag)
	}
	return nil
}

// MarshalBERIsdArgType encodes a IsdArgType list to BER.
func MarshalBERIsdArgType(list IsdArgType) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERIsdArgType decodes a IsdArgType list from BER.
func UnmarshalBERIsdArgType(data []byte) (IsdArgType, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding IsdArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "IsdArgType", Cause: ber.ErrExtraData}
	}
	var result IsdArgType
	offset := 0
	for offset < len(content) {
		var elem IsdArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes IsdArgData to BER format.
func (v *IsdArgData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrivateFeatureCode != nil {
		enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		enc_privatefeaturecode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_privatefeaturecode)
		children = append(children, enc_privatefeaturecode...)
	}
	if v.PrivateFeatureData != nil {
		enc_privatefeaturedata, err := v.PrivateFeatureData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding privateFeatureData: %w", err)
		}
		children = append(children, enc_privatefeaturedata...)
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

// MarshalDER encodes IsdArgData to DER format.
func (v *IsdArgData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IsdArgData from BER/DER format.
func (v *IsdArgData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IsdArgData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IsdArgData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateFeatureCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				offset += n_privatefeaturecode
			}
		}
	}
	// Decode privateFeatureData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) {
				// Decode nested CHOICE (PrivateFeatureData)
				_, n_privatefeaturedata, _, tlvErr_privatefeaturedata := ber.DecodeTLV(content[offset:])
				if tlvErr_privatefeaturedata != nil {
					return fmt.Errorf("decoding privateFeatureData: %w", tlvErr_privatefeaturedata)
				}
				var dec_privatefeaturedata PrivateFeatureData
				if unmErr := dec_privatefeaturedata.UnmarshalBER(content[offset : offset+n_privatefeaturedata]); unmErr != nil {
					return fmt.Errorf("decoding privateFeatureData: %w", unmErr)
				}
				v.PrivateFeatureData = &dec_privatefeaturedata
				offset += n_privatefeaturedata
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IsdArgData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PrivateFeatureData to BER format.
func (v *PrivateFeatureData) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case PrivateFeatureDataChoiceSubscriptionTypeInfo:
		if v.SubscriptionTypeInfo == nil {
			return nil, fmt.Errorf("choice PrivateFeatureData: subscriptionTypeInfo is nil")
		}
		enc_0, err := v.SubscriptionTypeInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding subscriptionTypeInfo: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_0)
		return enc_0, nil
	case PrivateFeatureDataChoiceOickInfo:
		if v.OickInfo == nil {
			return nil, fmt.Errorf("choice PrivateFeatureData: oickInfo is nil")
		}
		enc_1, err := v.OickInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding oickInfo: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PrivateFeatureData", v.Choice)
	}
}

// MarshalDER encodes PrivateFeatureData to DER format.
func (v *PrivateFeatureData) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case PrivateFeatureDataChoiceSubscriptionTypeInfo:
		if v.SubscriptionTypeInfo == nil {
			return nil, fmt.Errorf("choice PrivateFeatureData: subscriptionTypeInfo is nil")
		}
		enc_der_0, err := v.SubscriptionTypeInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding subscriptionTypeInfo: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_der_0)
		return enc_der_0, nil
	case PrivateFeatureDataChoiceOickInfo:
		if v.OickInfo == nil {
			return nil, fmt.Errorf("choice PrivateFeatureData: oickInfo is nil")
		}
		enc_der_1, err := v.OickInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding oickInfo: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, true, enc_der_1)
		return enc_der_1, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes PrivateFeatureData from BER/DER format.
func (v *PrivateFeatureData) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for PrivateFeatureData CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PrivateFeatureData: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding PrivateFeatureData CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PrivateFeatureData", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = PrivateFeatureDataChoiceSubscriptionTypeInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding subscriptionTypeInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SubscriptionTypeInfo
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding subscriptionTypeInfo: %w", unmErr)
		}
		v.SubscriptionTypeInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
		v.Choice = PrivateFeatureDataChoiceOickInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding oickInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec OickInfo
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding oickInfo: %w", unmErr)
		}
		v.OickInfo = &dec
	} else {
		return fmt.Errorf("unknown tag %s for PrivateFeatureData CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes OickInfo to BER format.
func (v *OickInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	children = append(children, enc_ssstatus...)
	enc_incategorykey := ber.EncodeOctetString([]byte(v.InCategoryKey))
	children = append(children, enc_incategorykey...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes OickInfo to DER format.
func (v *OickInfo) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes OickInfo from BER/DER format.
func (v *OickInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding OickInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "OickInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Status
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Status")
	}
	val_ssstatus, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Status: %w", err)
	}
	v.SsStatus = ExtSSStatus4(val_ssstatus)
	offset += n
	// Decode inCategoryKey
	if offset >= len(content) {
		return fmt.Errorf("missing required field inCategoryKey")
	}
	val_incategorykey, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding inCategoryKey: %w", err)
	}
	v.InCategoryKey = INCategoryKey(val_incategorykey)
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "OickInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SubscriptionTypeInfo to BER format.
func (v *SubscriptionTypeInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_subscriptiontype := ber.EncodeOctetString([]byte(v.SubscriptionType))
	children = append(children, enc_subscriptiontype...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SubscriptionTypeInfo to DER format.
func (v *SubscriptionTypeInfo) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SubscriptionTypeInfo from BER/DER format.
func (v *SubscriptionTypeInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SubscriptionTypeInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriptionTypeInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode subscriptionType
	if offset >= len(content) {
		return fmt.Errorf("missing required field subscriptionType")
	}
	val_subscriptiontype, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding subscriptionType: %w", err)
	}
	v.SubscriptionType = SubscriptionType(val_subscriptiontype)
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SubscriptionTypeInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERIsdResType encodes a IsdResType list to BER.
func MarshalBERIsdResType(list IsdResType) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERIsdResType decodes a IsdResType list from BER.
func UnmarshalBERIsdResType(data []byte) (IsdResType, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding IsdResType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "IsdResType", Cause: ber.ErrExtraData}
	}
	var result IsdResType
	offset := 0
	for offset < len(content) {
		var elem IsdResData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes IsdResData to BER format.
func (v *IsdResData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SupportedPrivateFeature != nil {
		enc_supportedprivatefeature := ber.EncodeOctetString([]byte(*v.SupportedPrivateFeature))
		enc_supportedprivatefeature = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_supportedprivatefeature)
		children = append(children, enc_supportedprivatefeature...)
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

// MarshalDER encodes IsdResData to DER format.
func (v *IsdResData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes IsdResData from BER/DER format.
func (v *IsdResData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding IsdResData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "IsdResData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode supportedPrivateFeature
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_supportedprivatefeature, rawVal_supportedprivatefeature, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding supportedPrivateFeature: %w", err)
				}
				tmp_supportedprivatefeature := PrivateFeatureCode(rawVal_supportedprivatefeature)
				v.SupportedPrivateFeature = &tmp_supportedprivatefeature
				offset += n_supportedprivatefeature
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IsdResData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERDsdArgType encodes a DsdArgType list to BER.
func MarshalBERDsdArgType(list DsdArgType) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERDsdArgType decodes a DsdArgType list from BER.
func UnmarshalBERDsdArgType(data []byte) (DsdArgType, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding DsdArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "DsdArgType", Cause: ber.ErrExtraData}
	}
	var result DsdArgType
	offset := 0
	for offset < len(content) {
		var elem DsdArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes DsdArgData to BER format.
func (v *DsdArgData) MarshalBER() ([]byte, error) {
	var children []byte
	enc_privatefeaturewithdraw := ber.EncodeOctetString([]byte(v.PrivateFeatureWithdraw))
	children = append(children, enc_privatefeaturewithdraw...)
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes DsdArgData to DER format.
func (v *DsdArgData) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes DsdArgData from BER/DER format.
func (v *DsdArgData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding DsdArgData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DsdArgData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateFeatureWithdraw
	if offset >= len(content) {
		return fmt.Errorf("missing required field privateFeatureWithdraw")
	}
	val_privatefeaturewithdraw, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding privateFeatureWithdraw: %w", err)
	}
	v.PrivateFeatureWithdraw = PrivateFeatureCode(val_privatefeaturewithdraw)
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DsdArgData", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERSRIArgType encodes a SRIArgType list to BER.
func MarshalBERSRIArgType(list SRIArgType) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSRIArgType decodes a SRIArgType list from BER.
func UnmarshalBERSRIArgType(data []byte) (SRIArgType, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SRIArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SRIArgType", Cause: ber.ErrExtraData}
	}
	var result SRIArgType
	offset := 0
	for offset < len(content) {
		var elem SriArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes SriArgData to BER format.
func (v *SriArgData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrivateFeatureCode != nil {
		enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		enc_privatefeaturecode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_privatefeaturecode)
		children = append(children, enc_privatefeaturecode...)
	}
	if v.ExtraNetworkInfo != nil {
		enc_extranetworkinfo, err := v.ExtraNetworkInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extraNetworkInfo: %w", err)
		}
		enc_extranetworkinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_extranetworkinfo)
		children = append(children, enc_extranetworkinfo...)
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

// MarshalDER encodes SriArgData to DER format.
func (v *SriArgData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SriArgData from BER/DER format.
func (v *SriArgData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SriArgData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SriArgData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateFeatureCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				offset += n_privatefeaturecode
			}
		}
	}
	// Decode extraNetworkInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_extranetworkinfo, rawVal_extranetworkinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extraNetworkInfo: %w", err)
				}
				reconstructed_extranetworkinfo := ber.EncodeSequence(rawVal_extranetworkinfo)
				var dec_extranetworkinfo ExtraSignalInfo
				if unmErr := dec_extranetworkinfo.UnmarshalBER(reconstructed_extranetworkinfo); unmErr != nil {
					return fmt.Errorf("decoding extraNetworkInfo: %w", unmErr)
				}
				v.ExtraNetworkInfo = &dec_extranetworkinfo
				offset += n_extranetworkinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SriArgData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSRIResType encodes a SRIResType list to BER.
func MarshalBERSRIResType(list SRIResType) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSRIResType decodes a SRIResType list from BER.
func UnmarshalBERSRIResType(data []byte) (SRIResType, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SRIResType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SRIResType", Cause: ber.ErrExtraData}
	}
	var result SRIResType
	offset := 0
	for offset < len(content) {
		var elem SriResData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes SriResData to BER format.
func (v *SriResData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrivateFeatureCode != nil {
		enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		enc_privatefeaturecode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_privatefeaturecode)
		children = append(children, enc_privatefeaturecode...)
	}
	if v.InCategoryKey != nil {
		enc_incategorykey := ber.EncodeOctetString([]byte(*v.InCategoryKey))
		enc_incategorykey = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_incategorykey)
		children = append(children, enc_incategorykey...)
	}
	if v.SubscriptionType != nil {
		enc_subscriptiontype := ber.EncodeOctetString([]byte(*v.SubscriptionType))
		enc_subscriptiontype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_subscriptiontype)
		children = append(children, enc_subscriptiontype...)
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

// MarshalDER encodes SriResData to DER format.
func (v *SriResData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SriResData from BER/DER format.
func (v *SriResData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SriResData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SriResData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateFeatureCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				offset += n_privatefeaturecode
			}
		}
	}
	// Decode inCategoryKey
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_incategorykey, rawVal_incategorykey, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding inCategoryKey: %w", err)
				}
				tmp_incategorykey := INCategoryKey(rawVal_incategorykey)
				v.InCategoryKey = &tmp_incategorykey
				offset += n_incategorykey
			}
		}
	}
	// Decode subscriptionType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				_, n_subscriptiontype, rawVal_subscriptiontype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding subscriptionType: %w", err)
				}
				tmp_subscriptiontype := SubscriptionType(rawVal_subscriptiontype)
				v.SubscriptionType = &tmp_subscriptiontype
				offset += n_subscriptiontype
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SriResData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERPrnArgType encodes a PrnArgType list to BER.
func MarshalBERPrnArgType(list PrnArgType) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERPrnArgType decodes a PrnArgType list from BER.
func UnmarshalBERPrnArgType(data []byte) (PrnArgType, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding PrnArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PrnArgType", Cause: ber.ErrExtraData}
	}
	var result PrnArgType
	offset := 0
	for offset < len(content) {
		var elem PrnArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes PrnArgData to BER format.
func (v *PrnArgData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrivateFeatureCode != nil {
		enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		enc_privatefeaturecode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_privatefeaturecode)
		children = append(children, enc_privatefeaturecode...)
	}
	if v.ExtraNetworkInfo != nil {
		enc_extranetworkinfo, err := v.ExtraNetworkInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extraNetworkInfo: %w", err)
		}
		enc_extranetworkinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_extranetworkinfo)
		children = append(children, enc_extranetworkinfo...)
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

// MarshalDER encodes PrnArgData to DER format.
func (v *PrnArgData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes PrnArgData from BER/DER format.
func (v *PrnArgData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding PrnArgData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PrnArgData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateFeatureCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				offset += n_privatefeaturecode
			}
		}
	}
	// Decode extraNetworkInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_extranetworkinfo, rawVal_extranetworkinfo, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extraNetworkInfo: %w", err)
				}
				reconstructed_extranetworkinfo := ber.EncodeSequence(rawVal_extranetworkinfo)
				var dec_extranetworkinfo ExtraSignalInfo
				if unmErr := dec_extranetworkinfo.UnmarshalBER(reconstructed_extranetworkinfo); unmErr != nil {
					return fmt.Errorf("decoding extraNetworkInfo: %w", unmErr)
				}
				v.ExtraNetworkInfo = &dec_extranetworkinfo
				offset += n_extranetworkinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrnArgData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERUlArgType encodes a UlArgType list to BER.
func MarshalBERUlArgType(list UlArgType) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERUlArgType decodes a UlArgType list from BER.
func UnmarshalBERUlArgType(data []byte) (UlArgType, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding UlArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "UlArgType", Cause: ber.ErrExtraData}
	}
	var result UlArgType
	offset := 0
	for offset < len(content) {
		var elem UlArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes UlArgData to BER format.
func (v *UlArgData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrivateFeatureCode != nil {
		enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		enc_privatefeaturecode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_privatefeaturecode)
		children = append(children, enc_privatefeaturecode...)
	}
	if v.PrivateFeatureUlArgData != nil {
		enc_privatefeatureulargdata, err := v.PrivateFeatureUlArgData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding privateFeatureUlArgData: %w", err)
		}
		children = append(children, enc_privatefeatureulargdata...)
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

// MarshalDER encodes UlArgData to DER format.
func (v *UlArgData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes UlArgData from BER/DER format.
func (v *UlArgData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding UlArgData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UlArgData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateFeatureCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				offset += n_privatefeaturecode
			}
		}
	}
	// Decode privateFeatureUlArgData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				// Decode nested CHOICE (PrivateFeatureUlArgData)
				_, n_privatefeatureulargdata, _, tlvErr_privatefeatureulargdata := ber.DecodeTLV(content[offset:])
				if tlvErr_privatefeatureulargdata != nil {
					return fmt.Errorf("decoding privateFeatureUlArgData: %w", tlvErr_privatefeatureulargdata)
				}
				var dec_privatefeatureulargdata PrivateFeatureUlArgData
				if unmErr := dec_privatefeatureulargdata.UnmarshalBER(content[offset : offset+n_privatefeatureulargdata]); unmErr != nil {
					return fmt.Errorf("decoding privateFeatureUlArgData: %w", unmErr)
				}
				v.PrivateFeatureUlArgData = &dec_privatefeatureulargdata
				offset += n_privatefeatureulargdata
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UlArgData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes PrivateFeatureUlArgData to BER format.
func (v *PrivateFeatureUlArgData) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case PrivateFeatureUlArgDataChoiceAdc:
		enc_0 := ber.EncodeOctetString([]byte(*v.Adc))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_0)
		return enc_0, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PrivateFeatureUlArgData", v.Choice)
	}
}

// MarshalDER encodes PrivateFeatureUlArgData to DER format.
func (v *PrivateFeatureUlArgData) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes PrivateFeatureUlArgData from BER/DER format.
func (v *PrivateFeatureUlArgData) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for PrivateFeatureUlArgData CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PrivateFeatureUlArgData: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding PrivateFeatureUlArgData CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PrivateFeatureUlArgData", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = PrivateFeatureUlArgDataChoiceAdc
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding adc: %w", tlvErr)
		}
		tmp := IMEI4(rawVal)
		v.Adc = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for PrivateFeatureUlArgData CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtraSignalInfo to BER format.
func (v *ExtraSignalInfo) MarshalBER() ([]byte, error) {
	var children []byte
	enc_protocolid := ber.EncodeInteger(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	children = append(children, enc_signalinfo...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 1, Constructed: true}, children), nil
}

// MarshalDER encodes ExtraSignalInfo to DER format.
func (v *ExtraSignalInfo) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ExtraSignalInfo from BER/DER format.
func (v *ExtraSignalInfo) UnmarshalBER(data []byte) error {
	decodedTag, content, total, err := ber.DecodeConstructedContent(data)
	if err != nil {
		return fmt.Errorf("decoding ExtraSignalInfo: %w", err)
	}
	if decodedTag.Class != tag.ClassPrivate || decodedTag.Number != 1 || !decodedTag.Constructed {
		return fmt.Errorf("decoding ExtraSignalInfo: %w: expected tag [PRIVATE 1], got %s", ber.ErrInvalidTag, decodedTag)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtraSignalInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocolId
	if offset >= len(content) {
		return fmt.Errorf("missing required field protocolId")
	}
	val_protocolid, n, err := ber.DecodeInteger(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding protocolId: %w", err)
	}
	v.ProtocolId = ExtraProtocolId(val_protocolid)
	offset += n
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo4(val_signalinfo)
	offset += n
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExtraSignalInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SaiArgType to BER format.
func (v *SaiArgType) MarshalBER() ([]byte, error) {
	var children []byte
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeNull()
		enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_msisdn)
		children = append(children, enc_msisdn...)
	}
	if v.NoAuthenVectorsRequested != nil {
		enc_noauthenvectorsrequested := ber.EncodeNull()
		enc_noauthenvectorsrequested = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_noauthenvectorsrequested)
		children = append(children, enc_noauthenvectorsrequested...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SaiArgType to DER format.
func (v *SaiArgType) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SaiArgType from BER/DER format.
func (v *SaiArgType) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SaiArgType SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SaiArgType", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				_ = rawVal_msisdn
				v.Msisdn = &struct{}{}
				offset += n_msisdn
			}
		}
	}
	// Decode noAuthenVectorsRequested
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_noauthenvectorsrequested, rawVal_noauthenvectorsrequested, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding noAuthenVectorsRequested: %w", err)
				}
				_ = rawVal_noauthenvectorsrequested
				v.NoAuthenVectorsRequested = &struct{}{}
				offset += n_noauthenvectorsrequested
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SaiArgType", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SaiResType to BER format.
func (v *SaiResType) MarshalBER() ([]byte, error) {
	var children []byte
	if v.MsIsdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.MsIsdn))
		enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_msisdn)
		children = append(children, enc_msisdn...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes SaiResType to DER format.
func (v *SaiResType) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SaiResType from BER/DER format.
func (v *SaiResType) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SaiResType SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SaiResType", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msIsdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msIsdn: %w", err)
				}
				tmp_msisdn := ISDNAddressString4(rawVal_msisdn)
				v.MsIsdn = &tmp_msisdn
				offset += n_msisdn
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SaiResType", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AtiArgType to BER format.
func (v *AtiArgType) MarshalBER() ([]byte, error) {
	var children []byte
	if v.RequestedInfoType != nil {
		enc_requestedinfotype, err := v.RequestedInfoType.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding requestedInfoType: %w", err)
		}
		enc_requestedinfotype = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_requestedinfotype)
		children = append(children, enc_requestedinfotype...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AtiArgType to DER format.
func (v *AtiArgType) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AtiArgType from BER/DER format.
func (v *AtiArgType) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AtiArgType SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AtiArgType", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode requestedInfoType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_requestedinfotype, rawVal_requestedinfotype, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding requestedInfoType: %w", err)
				}
				reconstructed_requestedinfotype := ber.EncodeSequence(rawVal_requestedinfotype)
				var dec_requestedinfotype RequestedInfoType
				if unmErr := dec_requestedinfotype.UnmarshalBER(reconstructed_requestedinfotype); unmErr != nil {
					return fmt.Errorf("decoding requestedInfoType: %w", unmErr)
				}
				v.RequestedInfoType = &dec_requestedinfotype
				offset += n_requestedinfotype
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AtiArgType", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AtiResType to BER format.
func (v *AtiResType) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ToBeDecided != nil {
		enc_tobedecided := ber.EncodeNull()
		enc_tobedecided = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_tobedecided)
		children = append(children, enc_tobedecided...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes AtiResType to DER format.
func (v *AtiResType) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AtiResType from BER/DER format.
func (v *AtiResType) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AtiResType SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AtiResType", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode toBeDecided
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_tobedecided, rawVal_tobedecided, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding toBeDecided: %w", err)
				}
				_ = rawVal_tobedecided
				v.ToBeDecided = &struct{}{}
				offset += n_tobedecided
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AtiResType", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RdArgType to BER format.
func (v *RdArgType) MarshalBER() ([]byte, error) {
	var children []byte
	if v.ToBeDecidedOne != nil {
		enc_tobedecidedone := ber.EncodeNull()
		enc_tobedecidedone = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_tobedecidedone)
		children = append(children, enc_tobedecidedone...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes RdArgType to DER format.
func (v *RdArgType) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RdArgType from BER/DER format.
func (v *RdArgType) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RdArgType SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RdArgType", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode toBeDecidedOne
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_tobedecidedone, rawVal_tobedecidedone, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding toBeDecidedOne: %w", err)
				}
				_ = rawVal_tobedecidedone
				v.ToBeDecidedOne = &struct{}{}
				offset += n_tobedecidedone
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "RdArgType", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes RequestedInfoType to BER format.
func (v *RequestedInfoType) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SgsnNumber != nil {
		enc_sgsnnumber := ber.EncodeNull()
		enc_sgsnnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_sgsnnumber)
		children = append(children, enc_sgsnnumber...)
	}
	return ber.EncodeSequence(children), nil
}

// MarshalDER encodes RequestedInfoType to DER format.
func (v *RequestedInfoType) MarshalDER() ([]byte, error) {
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RequestedInfoType from BER/DER format.
func (v *RequestedInfoType) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RequestedInfoType SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RequestedInfoType", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sgsnNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_sgsnnumber, rawVal_sgsnnumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding sgsnNumber: %w", err)
				}
				_ = rawVal_sgsnnumber
				v.SgsnNumber = &struct{}{}
				offset += n_sgsnnumber
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "RequestedInfoType", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERExtAtiArgType encodes a ExtAtiArgType list to BER.
func MarshalBERExtAtiArgType(list ExtAtiArgType) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERExtAtiArgType decodes a ExtAtiArgType list from BER.
func UnmarshalBERExtAtiArgType(data []byte) (ExtAtiArgType, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ExtAtiArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ExtAtiArgType", Cause: ber.ErrExtraData}
	}
	var result ExtAtiArgType
	offset := 0
	for offset < len(content) {
		var elem AtiArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:])
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if unmErr := elem.UnmarshalBER(content[offset : offset+n]); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		offset += n
	}
	return result, nil
}

// MarshalBER encodes AtiArgData to BER format.
func (v *AtiArgData) MarshalBER() ([]byte, error) {
	var children []byte
	if v.PrivateFeatureCode != nil {
		enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		enc_privatefeaturecode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_privatefeaturecode)
		children = append(children, enc_privatefeaturecode...)
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

// MarshalDER encodes AtiArgData to DER format.
func (v *AtiArgData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes AtiArgData from BER/DER format.
func (v *AtiArgData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding AtiArgData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AtiArgData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode privateFeatureCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				offset += n_privatefeaturecode
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "AtiArgData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
