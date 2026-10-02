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

// EnhancedCheckIMEIArg represents the ASN.1 type EnhancedCheckIMEI-Arg (SEQUENCE).
type EnhancedCheckIMEIArg struct {
	Imei                   IMEI5                    `asn1:""`
	RequestedEquipmentInfo *RequestedEquipmentInfo5 `asn1:",optional" json:"RequestedEquipmentInfo,omitempty"`
	Imsi                   *IMSI5                   `asn1:"tag:1,private,implicit,optional" json:"Imsi,omitempty"`
	LocationInformation    []byte                   `asn1:"tag:3,private,implicit,optional" json:"LocationInformation,omitempty"`
	ExtensionContainer     *ExtensionContainer5     `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_              int64                    `asn1:"-" json:"-"`
	ExtPresent_            []bool                   `asn1:"-" json:"-"`
	ExtData_               [][]byte                 `asn1:"-" json:"-"`
	berOriginal_           []byte                   `asn1:"-" json:"-"`
	berSnapshot_           []byte                   `asn1:"-" json:"-"`
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
	berOriginal_  []byte         `json:"-"`
	berSnapshot_  []byte         `json:"-"`
	IsdArgType    *IsdArgType    `json:"IsdArgType,omitempty"`
	IsdResType    *IsdResType    `json:"IsdResType,omitempty"`
	DsdArgType    *DsdArgType    `json:"DsdArgType,omitempty"`
	SriArgType    *SRIArgType    `json:"SriArgType,omitempty"`
	SriResType    *SRIResType    `json:"SriResType,omitempty"`
	PrnArgType    *PrnArgType    `json:"PrnArgType,omitempty"`
	UlArgType     *UlArgType     `json:"UlArgType,omitempty"`
	RdArgType     *RdArgType     `json:"RdArgType,omitempty"`
	SaiArgType    *SaiArgType    `json:"SaiArgType,omitempty"`
	SaiResType    *SaiResType    `json:"SaiResType,omitempty"`
	AtiArgType    *AtiArgType    `json:"AtiArgType,omitempty"`
	AtiResType    *AtiResType    `json:"AtiResType,omitempty"`
	ExtAtiArgType *ExtAtiArgType `json:"ExtAtiArgType,omitempty"`
}

// NewExtensionTypeIsdArgType creates a ExtensionType with the isdArgType alternative.
func NewExtensionTypeIsdArgType(v *IsdArgType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceIsdArgType,
		IsdArgType: v,
	}
}

// NewExtensionTypeIsdResType creates a ExtensionType with the isdResType alternative.
func NewExtensionTypeIsdResType(v *IsdResType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceIsdResType,
		IsdResType: v,
	}
}

// NewExtensionTypeDsdArgType creates a ExtensionType with the dsdArgType alternative.
func NewExtensionTypeDsdArgType(v *DsdArgType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceDsdArgType,
		DsdArgType: v,
	}
}

// NewExtensionTypeSriArgType creates a ExtensionType with the sriArgType alternative.
func NewExtensionTypeSriArgType(v *SRIArgType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceSriArgType,
		SriArgType: v,
	}
}

// NewExtensionTypeSriResType creates a ExtensionType with the sriResType alternative.
func NewExtensionTypeSriResType(v *SRIResType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoiceSriResType,
		SriResType: v,
	}
}

// NewExtensionTypePrnArgType creates a ExtensionType with the prnArgType alternative.
func NewExtensionTypePrnArgType(v *PrnArgType) ExtensionType {
	return ExtensionType{
		Choice:     ExtensionTypeChoicePrnArgType,
		PrnArgType: v,
	}
}

// NewExtensionTypeUlArgType creates a ExtensionType with the ulArgType alternative.
func NewExtensionTypeUlArgType(v *UlArgType) ExtensionType {
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
func NewExtensionTypeExtAtiArgType(v *ExtAtiArgType) ExtensionType {
	return ExtensionType{
		Choice:        ExtensionTypeChoiceExtAtiArgType,
		ExtAtiArgType: v,
	}
}

// IsdArgType represents the ASN.1 type IsdArgType (SEQUENCE_OF).
type IsdArgType struct {
	Values       []IsdArgData `json:"Values"`
	berOriginal_ []byte       `json:"-"`
	berSnapshot_ []byte       `json:"-"`
}

// IsdArgData represents the ASN.1 type IsdArgData (SEQUENCE).
type IsdArgData struct {
	PrivateFeatureCode *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	PrivateFeatureData *PrivateFeatureData `asn1:",optional" json:"PrivateFeatureData,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// PrivateFeatureData choice constants.
const (
	PrivateFeatureDataChoiceSubscriptionTypeInfo = 1
	PrivateFeatureDataChoiceOickInfo             = 2
)

// PrivateFeatureData represents the ASN.1 CHOICE type PrivateFeatureData.
type PrivateFeatureData struct {
	Choice               int
	berOriginal_         []byte                `json:"-"`
	berSnapshot_         []byte                `json:"-"`
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
	SsStatus      ExtSSStatus5  `asn1:""`
	InCategoryKey INCategoryKey `asn1:""`
	berOriginal_  []byte        `asn1:"-" json:"-"`
	berSnapshot_  []byte        `asn1:"-" json:"-"`
}

// INCategoryKey represents the ASN.1 type INCategoryKey (OCTET_STRING).
type INCategoryKey = TBCDSTRING5

// SubscriptionTypeInfo represents the ASN.1 type SubscriptionTypeInfo (SEQUENCE).
type SubscriptionTypeInfo struct {
	SubscriptionType SubscriptionType `asn1:""`
	berOriginal_     []byte           `asn1:"-" json:"-"`
	berSnapshot_     []byte           `asn1:"-" json:"-"`
}

// SubscriptionType represents the ASN.1 type SubscriptionType (OCTET_STRING).
type SubscriptionType = []byte

// IsdResType represents the ASN.1 type IsdResType (SEQUENCE_OF).
type IsdResType struct {
	Values       []IsdResData `json:"Values"`
	berOriginal_ []byte       `json:"-"`
	berSnapshot_ []byte       `json:"-"`
}

// IsdResData represents the ASN.1 type IsdResData (SEQUENCE).
type IsdResData struct {
	SupportedPrivateFeature *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"SupportedPrivateFeature,omitempty"`
	ExtCount_               int64               `asn1:"-" json:"-"`
	ExtPresent_             []bool              `asn1:"-" json:"-"`
	ExtData_                [][]byte            `asn1:"-" json:"-"`
	berOriginal_            []byte              `asn1:"-" json:"-"`
	berSnapshot_            []byte              `asn1:"-" json:"-"`
}

// DsdArgType represents the ASN.1 type DsdArgType (SEQUENCE_OF).
type DsdArgType struct {
	Values       []DsdArgData `json:"Values"`
	berOriginal_ []byte       `json:"-"`
	berSnapshot_ []byte       `json:"-"`
}

// DsdArgData represents the ASN.1 type DsdArgData (SEQUENCE).
type DsdArgData struct {
	PrivateFeatureWithdraw PrivateFeatureCode `asn1:""`
	berOriginal_           []byte             `asn1:"-" json:"-"`
	berSnapshot_           []byte             `asn1:"-" json:"-"`
}

// SRIArgType represents the ASN.1 type SRIArgType (SEQUENCE_OF).
type SRIArgType struct {
	Values       []SriArgData `json:"Values"`
	berOriginal_ []byte       `json:"-"`
	berSnapshot_ []byte       `json:"-"`
}

// SriArgData represents the ASN.1 type SriArgData (SEQUENCE).
type SriArgData struct {
	PrivateFeatureCode *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	ExtraNetworkInfo   *ExtraSignalInfo    `asn1:"tag:2,context,implicit,optional" json:"ExtraNetworkInfo,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// SRIResType represents the ASN.1 type SRIResType (SEQUENCE_OF).
type SRIResType struct {
	Values       []SriResData `json:"Values"`
	berOriginal_ []byte       `json:"-"`
	berSnapshot_ []byte       `json:"-"`
}

// SriResData represents the ASN.1 type SriResData (SEQUENCE).
type SriResData struct {
	PrivateFeatureCode *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	InCategoryKey      *INCategoryKey      `asn1:"tag:2,context,implicit,optional" json:"InCategoryKey,omitempty"`
	SubscriptionType   *SubscriptionType   `asn1:"tag:5,context,implicit,optional" json:"SubscriptionType,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// PrnArgType represents the ASN.1 type PrnArgType (SEQUENCE_OF).
type PrnArgType struct {
	Values       []PrnArgData `json:"Values"`
	berOriginal_ []byte       `json:"-"`
	berSnapshot_ []byte       `json:"-"`
}

// PrnArgData represents the ASN.1 type PrnArgData (SEQUENCE).
type PrnArgData struct {
	PrivateFeatureCode *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	ExtraNetworkInfo   *ExtraSignalInfo    `asn1:"tag:2,context,implicit,optional" json:"ExtraNetworkInfo,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// UlArgType represents the ASN.1 type UlArgType (SEQUENCE_OF).
type UlArgType struct {
	Values       []UlArgData `json:"Values"`
	berOriginal_ []byte      `json:"-"`
	berSnapshot_ []byte      `json:"-"`
}

// UlArgData represents the ASN.1 type UlArgData (SEQUENCE).
type UlArgData struct {
	PrivateFeatureCode      *PrivateFeatureCode      `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	PrivateFeatureUlArgData *PrivateFeatureUlArgData `asn1:",optional" json:"PrivateFeatureUlArgData,omitempty"`
	ExtCount_               int64                    `asn1:"-" json:"-"`
	ExtPresent_             []bool                   `asn1:"-" json:"-"`
	ExtData_                [][]byte                 `asn1:"-" json:"-"`
	berOriginal_            []byte                   `asn1:"-" json:"-"`
	berSnapshot_            []byte                   `asn1:"-" json:"-"`
}

// PrivateFeatureUlArgData choice constants.
const (
	PrivateFeatureUlArgDataChoiceAdc = 1
)

// PrivateFeatureUlArgData represents the ASN.1 CHOICE type PrivateFeatureUlArgData.
type PrivateFeatureUlArgData struct {
	Choice       int
	berOriginal_ []byte `json:"-"`
	berSnapshot_ []byte `json:"-"`
	Adc          *IMEI5 `json:"Adc,omitempty"`
}

// NewPrivateFeatureUlArgDataAdc creates a PrivateFeatureUlArgData with the adc alternative.
func NewPrivateFeatureUlArgDataAdc(v IMEI5) PrivateFeatureUlArgData {
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
	ProtocolId   ExtraProtocolId `asn1:""`
	SignalInfo   SignalInfo5     `asn1:""`
	berOriginal_ []byte          `asn1:"-" json:"-"`
	berSnapshot_ []byte          `asn1:"-" json:"-"`
}

// SaiArgType represents the ASN.1 type SaiArgType (SEQUENCE).
type SaiArgType struct {
	Msisdn                   *struct{} `asn1:"tag:1,context,implicit,optional" json:"Msisdn,omitempty"`
	NoAuthenVectorsRequested *struct{} `asn1:"tag:2,context,implicit,optional" json:"NoAuthenVectorsRequested,omitempty"`
	berOriginal_             []byte    `asn1:"-" json:"-"`
	berSnapshot_             []byte    `asn1:"-" json:"-"`
}

// SaiResType represents the ASN.1 type SaiResType (SEQUENCE).
type SaiResType struct {
	MsIsdn       *ISDNAddressString5 `asn1:"tag:1,context,implicit,optional" json:"MsIsdn,omitempty"`
	berOriginal_ []byte              `asn1:"-" json:"-"`
	berSnapshot_ []byte              `asn1:"-" json:"-"`
}

// AtiArgType represents the ASN.1 type AtiArgType (SEQUENCE).
type AtiArgType struct {
	RequestedInfoType *RequestedInfoType `asn1:"tag:0,context,implicit,optional" json:"RequestedInfoType,omitempty"`
	berOriginal_      []byte             `asn1:"-" json:"-"`
	berSnapshot_      []byte             `asn1:"-" json:"-"`
}

// AtiResType represents the ASN.1 type AtiResType (SEQUENCE).
type AtiResType struct {
	ToBeDecided  *struct{} `asn1:"tag:1,context,implicit,optional" json:"ToBeDecided,omitempty"`
	berOriginal_ []byte    `asn1:"-" json:"-"`
	berSnapshot_ []byte    `asn1:"-" json:"-"`
}

// RdArgType represents the ASN.1 type RdArgType (SEQUENCE).
type RdArgType struct {
	ToBeDecidedOne *struct{} `asn1:"tag:1,context,implicit,optional" json:"ToBeDecidedOne,omitempty"`
	berOriginal_   []byte    `asn1:"-" json:"-"`
	berSnapshot_   []byte    `asn1:"-" json:"-"`
}

// RequestedInfoType represents the ASN.1 type RequestedInfoType (SEQUENCE).
type RequestedInfoType struct {
	SgsnNumber   *struct{} `asn1:"tag:0,context,implicit,optional" json:"SgsnNumber,omitempty"`
	berOriginal_ []byte    `asn1:"-" json:"-"`
	berSnapshot_ []byte    `asn1:"-" json:"-"`
}

// ExtAtiArgType represents the ASN.1 type ExtAtiArgType (SEQUENCE_OF).
type ExtAtiArgType struct {
	Values       []AtiArgData `json:"Values"`
	berOriginal_ []byte       `json:"-"`
	berSnapshot_ []byte       `json:"-"`
}

// AtiArgData represents the ASN.1 type AtiArgData (SEQUENCE).
type AtiArgData struct {
	PrivateFeatureCode *PrivateFeatureCode `asn1:"tag:1,context,implicit,optional" json:"PrivateFeatureCode,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	ExtData_           [][]byte            `asn1:"-" json:"-"`
	berOriginal_       []byte              `asn1:"-" json:"-"`
	berSnapshot_       []byte              `asn1:"-" json:"-"`
}

// PrivateFeatureCode represents the ASN.1 type PrivateFeatureCode (OCTET_STRING).
type PrivateFeatureCode = []byte

// MarshalBER encodes EnhancedCheckIMEIArg to BER format.
func (v *EnhancedCheckIMEIArg) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EnhancedCheckIMEIArg receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EnhancedCheckIMEIArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imei) < 8 || len(v.Imei) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "imei", "SIZE (8)", len(v.Imei)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imei, encodeErr_enc_imei := ber.EncodeOctetString([]byte(v.Imei))
	if encodeErr_enc_imei != nil {
		return nil, fmt.Errorf("encoding imei: %w", encodeErr_enc_imei)
	}
	children = append(children, enc_imei...)
	if v.RequestedEquipmentInfo != nil {
		if (*v.RequestedEquipmentInfo).BitLength < 2 || (*v.RequestedEquipmentInfo).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "requestedEquipmentInfo", "SIZE (2..8)", (*v.RequestedEquipmentInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:505
		if v.RequestedEquipmentInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_requestedequipmentinfo, encodeErr_enc_requestedequipmentinfo := ber.EncodeBitString(v.RequestedEquipmentInfo.Bytes, (8-(v.RequestedEquipmentInfo.BitLength%8))%8)
		if encodeErr_enc_requestedequipmentinfo != nil {
			return nil, fmt.Errorf("encoding requestedEquipmentInfo: %w", encodeErr_enc_requestedequipmentinfo)
		}
		children = append(children, enc_requestedequipmentinfo...)
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
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.LocationInformation != nil {
		if len(v.LocationInformation) < 1 || len(v.LocationInformation) > 7 {
			if constraintErr := ber.CheckEncodedLength(opts, "locationInformation", "SIZE (1..7)", len(v.LocationInformation)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locationinformation, encodeErr_enc_locationinformation := ber.EncodeOctetString(v.LocationInformation)
		if encodeErr_enc_locationinformation != nil {
			return nil, fmt.Errorf("encoding locationInformation: %w", encodeErr_enc_locationinformation)
		}
		retagged_enc_locationinformation, tagErr_enc_locationinformation := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 3, enc_locationinformation)
		if tagErr_enc_locationinformation != nil {
			return nil, fmt.Errorf("encoding locationInformation: %w", tagErr_enc_locationinformation)
		}
		enc_locationinformation = retagged_enc_locationinformation
		children = append(children, enc_locationinformation...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes EnhancedCheckIMEIArg to DER format.
func (v *EnhancedCheckIMEIArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EnhancedCheckIMEIArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imei) < 8 || len(v.Imei) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "imei", "SIZE (8)", len(v.Imei)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imei, encodeErr_enc_imei := ber.EncodeOctetString([]byte(v.Imei))
	if encodeErr_enc_imei != nil {
		return nil, fmt.Errorf("encoding imei: %w", encodeErr_enc_imei)
	}
	children = append(children, enc_imei...)
	if v.RequestedEquipmentInfo != nil {
		if (*v.RequestedEquipmentInfo).BitLength < 2 || (*v.RequestedEquipmentInfo).BitLength > 8 {
			if constraintErr := ber.CheckEncodedLength(nil, "requestedEquipmentInfo", "SIZE (2..8)", (*v.RequestedEquipmentInfo).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:505
		if v.RequestedEquipmentInfo.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_requestedequipmentinfo, encodeErr_enc_requestedequipmentinfo := ber.EncodeBitString(v.RequestedEquipmentInfo.Bytes, (8-(v.RequestedEquipmentInfo.BitLength%8))%8)
		if encodeErr_enc_requestedequipmentinfo != nil {
			return nil, fmt.Errorf("encoding requestedEquipmentInfo: %w", encodeErr_enc_requestedequipmentinfo)
		}
		children = append(children, enc_requestedequipmentinfo...)
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
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 1, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.LocationInformation != nil {
		if len(v.LocationInformation) < 1 || len(v.LocationInformation) > 7 {
			if constraintErr := ber.CheckEncodedLength(nil, "locationInformation", "SIZE (1..7)", len(v.LocationInformation)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_locationinformation, encodeErr_enc_locationinformation := ber.EncodeOctetString(v.LocationInformation)
		if encodeErr_enc_locationinformation != nil {
			return nil, fmt.Errorf("encoding locationInformation: %w", encodeErr_enc_locationinformation)
		}
		retagged_enc_locationinformation, tagErr_enc_locationinformation := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 3, enc_locationinformation)
		if tagErr_enc_locationinformation != nil {
			return nil, fmt.Errorf("encoding locationInformation: %w", tagErr_enc_locationinformation)
		}
		enc_locationinformation = retagged_enc_locationinformation
		children = append(children, enc_locationinformation...)
	}
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
		return nil, fmt.Errorf("encoding EnhancedCheckIMEIArg as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EnhancedCheckIMEIArg from BER/DER format.
func (v *EnhancedCheckIMEIArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EnhancedCheckIMEIArg destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = EnhancedCheckIMEIArg{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
	val_imei, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding imei: %w", err)
	}
	v.Imei = IMEI5(val_imei)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.Imei) < 8 || len(v.Imei) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "imei", "SIZE (8)", len(v.Imei)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode requestedEquipmentInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 3 {
				bsBytes_requestedequipmentinfo, bsUnused_requestedequipmentinfo, n, err := ber.DecodeBitString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding requestedEquipmentInfo: %w", err)
				}
				bsBitLength_requestedequipmentinfo, bsLenErr_requestedequipmentinfo := ber.BitStringBitLength(len(bsBytes_requestedequipmentinfo), bsUnused_requestedequipmentinfo)
				if bsLenErr_requestedequipmentinfo != nil {
					return fmt.Errorf("decoding requestedEquipmentInfo: %w", bsLenErr_requestedequipmentinfo)
				}
				tmp_requestedequipmentinfo := runtime.BitString{Bytes: bsBytes_requestedequipmentinfo, BitLength: bsBitLength_requestedequipmentinfo}
				v.RequestedEquipmentInfo = &tmp_requestedequipmentinfo
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if (*v.RequestedEquipmentInfo).BitLength < 2 || (*v.RequestedEquipmentInfo).BitLength > 8 {
					if constraintErr := ber.CheckDecodedLength(opts, "requestedEquipmentInfo", "SIZE (2..8)", (*v.RequestedEquipmentInfo).BitLength); constraintErr != nil {
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
			if peekTag.Class == tag.ClassPrivate && peekTag.Number == 1 {
				decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding imsi: %w", err)
				}
				if decodedTag_imsi.Class != tag.ClassPrivate || decodedTag_imsi.Number != 1 {
					return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
				}
				tmp_imsi := IMSI5(rawVal_imsi)
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
	// Decode locationInformation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassPrivate && peekTag.Number == 3 {
				decodedTag_locationinformation, n_locationinformation, rawVal_locationinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding locationInformation: %w", err)
				}
				if decodedTag_locationinformation.Class != tag.ClassPrivate || decodedTag_locationinformation.Number != 3 {
					return fmt.Errorf("decoding locationInformation: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_locationinformation)
				}
				tmp_locationinformation := rawVal_locationinformation
				v.LocationInformation = tmp_locationinformation
				if offset < 0 || offset >
					len(content) || n_locationinformation < 0 || n_locationinformation >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_locationinformation
				if len(v.LocationInformation) < 1 || len(v.LocationInformation) > 7 {
					if constraintErr := ber.CheckDecodedLength(opts, "locationInformation", "SIZE (1..7)", len(v.LocationInformation)); constraintErr != nil {
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
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "EnhancedCheckIMEIArg", Cause: extErr_}
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

// MarshalBER encodes ExtensionType to BER format.
func (v *ExtensionType) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionType receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtensionType) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case ExtensionTypeChoiceIsdArgType:
		enc_0, err := MarshalBERIsdArgType(v.IsdArgType, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding isdArgType: %w", err)
		}
		if len((v.IsdArgType).Values) < 1 || len((v.IsdArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(opts, "isdArgType", "SIZE (1..50)", len((v.IsdArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding isdArgType: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case ExtensionTypeChoiceIsdResType:
		enc_1, err := MarshalBERIsdResType(v.IsdResType, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding isdResType: %w", err)
		}
		if len((v.IsdResType).Values) < 1 || len((v.IsdResType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(opts, "isdResType", "SIZE (1..50)", len((v.IsdResType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding isdResType: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case ExtensionTypeChoiceDsdArgType:
		enc_2, err := MarshalBERDsdArgType(v.DsdArgType, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding dsdArgType: %w", err)
		}
		if len((v.DsdArgType).Values) < 1 || len((v.DsdArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(opts, "dsdArgType", "SIZE (1..50)", len((v.DsdArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding dsdArgType: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case ExtensionTypeChoiceSriArgType:
		enc_3, err := MarshalBERSRIArgType(v.SriArgType, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding sriArgType: %w", err)
		}
		if len((v.SriArgType).Values) < 1 || len((v.SriArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(opts, "sriArgType", "SIZE (1..50)", len((v.SriArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding sriArgType: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	case ExtensionTypeChoiceSriResType:
		enc_4, err := MarshalBERSRIResType(v.SriResType, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding sriResType: %w", err)
		}
		if len((v.SriResType).Values) < 1 || len((v.SriResType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(opts, "sriResType", "SIZE (1..50)", len((v.SriResType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_4, tagErr_enc_4 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_4)
		if tagErr_enc_4 != nil {
			return nil, fmt.Errorf("encoding sriResType: %w", tagErr_enc_4)
		}
		enc_4 = retagged_enc_4
		return enc_4, nil
	case ExtensionTypeChoicePrnArgType:
		enc_5, err := MarshalBERPrnArgType(v.PrnArgType, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding prnArgType: %w", err)
		}
		if len((v.PrnArgType).Values) < 1 || len((v.PrnArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(opts, "prnArgType", "SIZE (1..50)", len((v.PrnArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_5, tagErr_enc_5 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_5)
		if tagErr_enc_5 != nil {
			return nil, fmt.Errorf("encoding prnArgType: %w", tagErr_enc_5)
		}
		enc_5 = retagged_enc_5
		return enc_5, nil
	case ExtensionTypeChoiceUlArgType:
		enc_6, err := MarshalBERUlArgType(v.UlArgType, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding ulArgType: %w", err)
		}
		if len((v.UlArgType).Values) < 1 || len((v.UlArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(opts, "ulArgType", "SIZE (1..50)", len((v.UlArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_6, tagErr_enc_6 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_6)
		if tagErr_enc_6 != nil {
			return nil, fmt.Errorf("encoding ulArgType: %w", tagErr_enc_6)
		}
		enc_6 = retagged_enc_6
		return enc_6, nil
	case ExtensionTypeChoiceRdArgType:
		if v.RdArgType == nil {
			return nil, fmt.Errorf("%w: choice ExtensionType: rdArgType is nil", ber.ErrInvalidValue)
		}
		enc_7, err := v.RdArgType.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding rdArgType: %w", err)
		}
		retagged_enc_7, tagErr_enc_7 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_7)
		if tagErr_enc_7 != nil {
			return nil, fmt.Errorf("encoding rdArgType: %w", tagErr_enc_7)
		}
		enc_7 = retagged_enc_7
		return enc_7, nil
	case ExtensionTypeChoiceSaiArgType:
		if v.SaiArgType == nil {
			return nil, fmt.Errorf("%w: choice ExtensionType: saiArgType is nil", ber.ErrInvalidValue)
		}
		enc_8, err := v.SaiArgType.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding saiArgType: %w", err)
		}
		retagged_enc_8, tagErr_enc_8 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_8)
		if tagErr_enc_8 != nil {
			return nil, fmt.Errorf("encoding saiArgType: %w", tagErr_enc_8)
		}
		enc_8 = retagged_enc_8
		return enc_8, nil
	case ExtensionTypeChoiceSaiResType:
		if v.SaiResType == nil {
			return nil, fmt.Errorf("%w: choice ExtensionType: saiResType is nil", ber.ErrInvalidValue)
		}
		enc_9, err := v.SaiResType.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding saiResType: %w", err)
		}
		retagged_enc_9, tagErr_enc_9 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_9)
		if tagErr_enc_9 != nil {
			return nil, fmt.Errorf("encoding saiResType: %w", tagErr_enc_9)
		}
		enc_9 = retagged_enc_9
		return enc_9, nil
	case ExtensionTypeChoiceAtiArgType:
		if v.AtiArgType == nil {
			return nil, fmt.Errorf("%w: choice ExtensionType: atiArgType is nil", ber.ErrInvalidValue)
		}
		enc_10, err := v.AtiArgType.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding atiArgType: %w", err)
		}
		retagged_enc_10, tagErr_enc_10 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_10)
		if tagErr_enc_10 != nil {
			return nil, fmt.Errorf("encoding atiArgType: %w", tagErr_enc_10)
		}
		enc_10 = retagged_enc_10
		return enc_10, nil
	case ExtensionTypeChoiceAtiResType:
		if v.AtiResType == nil {
			return nil, fmt.Errorf("%w: choice ExtensionType: atiResType is nil", ber.ErrInvalidValue)
		}
		enc_11, err := v.AtiResType.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding atiResType: %w", err)
		}
		retagged_enc_11, tagErr_enc_11 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_11)
		if tagErr_enc_11 != nil {
			return nil, fmt.Errorf("encoding atiResType: %w", tagErr_enc_11)
		}
		enc_11 = retagged_enc_11
		return enc_11, nil
	case ExtensionTypeChoiceExtAtiArgType:
		enc_12, err := MarshalBERExtAtiArgType(v.ExtAtiArgType, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding extAtiArgType: %w", err)
		}
		if len((v.ExtAtiArgType).Values) < 1 || len((v.ExtAtiArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(opts, "extAtiArgType", "SIZE (1..50)", len((v.ExtAtiArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_12, tagErr_enc_12 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_12)
		if tagErr_enc_12 != nil {
			return nil, fmt.Errorf("encoding extAtiArgType: %w", tagErr_enc_12)
		}
		enc_12 = retagged_enc_12
		return enc_12, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for ExtensionType", v.Choice)
	}
}

// MarshalDER encodes ExtensionType to DER format.
func (v *ExtensionType) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtensionType receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case ExtensionTypeChoiceIsdArgType:
		enc_der_0, err := MarshalDERIsdArgType(v.IsdArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding isdArgType: %w", err)
		}
		if len((v.IsdArgType).Values) < 1 || len((v.IsdArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(nil, "isdArgType", "SIZE (1..50)", len((v.IsdArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding isdArgType: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding isdArgType as DER: %w", derErr)
		}
		return enc_der_0, nil
	case ExtensionTypeChoiceIsdResType:
		enc_der_1, err := MarshalDERIsdResType(v.IsdResType)
		if err != nil {
			return nil, fmt.Errorf("encoding isdResType: %w", err)
		}
		if len((v.IsdResType).Values) < 1 || len((v.IsdResType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(nil, "isdResType", "SIZE (1..50)", len((v.IsdResType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding isdResType: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding isdResType as DER: %w", derErr)
		}
		return enc_der_1, nil
	case ExtensionTypeChoiceDsdArgType:
		enc_der_2, err := MarshalDERDsdArgType(v.DsdArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding dsdArgType: %w", err)
		}
		if len((v.DsdArgType).Values) < 1 || len((v.DsdArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(nil, "dsdArgType", "SIZE (1..50)", len((v.DsdArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, fmt.Errorf("encoding dsdArgType: %w", tagErr_enc_der_2)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding dsdArgType as DER: %w", derErr)
		}
		return enc_der_2, nil
	case ExtensionTypeChoiceSriArgType:
		enc_der_3, err := MarshalDERSRIArgType(v.SriArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding sriArgType: %w", err)
		}
		if len((v.SriArgType).Values) < 1 || len((v.SriArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(nil, "sriArgType", "SIZE (1..50)", len((v.SriArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, fmt.Errorf("encoding sriArgType: %w", tagErr_enc_der_3)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, fmt.Errorf("encoding sriArgType as DER: %w", derErr)
		}
		return enc_der_3, nil
	case ExtensionTypeChoiceSriResType:
		enc_der_4, err := MarshalDERSRIResType(v.SriResType)
		if err != nil {
			return nil, fmt.Errorf("encoding sriResType: %w", err)
		}
		if len((v.SriResType).Values) < 1 || len((v.SriResType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(nil, "sriResType", "SIZE (1..50)", len((v.SriResType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_4, tagErr_enc_der_4 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_der_4)
		if tagErr_enc_der_4 != nil {
			return nil, fmt.Errorf("encoding sriResType: %w", tagErr_enc_der_4)
		}
		enc_der_4 = retagged_enc_der_4
		if derErr := ber.ValidateDEREncodedElement(enc_der_4); derErr != nil {
			return nil, fmt.Errorf("encoding sriResType as DER: %w", derErr)
		}
		return enc_der_4, nil
	case ExtensionTypeChoicePrnArgType:
		enc_der_5, err := MarshalDERPrnArgType(v.PrnArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding prnArgType: %w", err)
		}
		if len((v.PrnArgType).Values) < 1 || len((v.PrnArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(nil, "prnArgType", "SIZE (1..50)", len((v.PrnArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_5, tagErr_enc_der_5 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_der_5)
		if tagErr_enc_der_5 != nil {
			return nil, fmt.Errorf("encoding prnArgType: %w", tagErr_enc_der_5)
		}
		enc_der_5 = retagged_enc_der_5
		if derErr := ber.ValidateDEREncodedElement(enc_der_5); derErr != nil {
			return nil, fmt.Errorf("encoding prnArgType as DER: %w", derErr)
		}
		return enc_der_5, nil
	case ExtensionTypeChoiceUlArgType:
		enc_der_6, err := MarshalDERUlArgType(v.UlArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding ulArgType: %w", err)
		}
		if len((v.UlArgType).Values) < 1 || len((v.UlArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(nil, "ulArgType", "SIZE (1..50)", len((v.UlArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_6, tagErr_enc_der_6 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_6)
		if tagErr_enc_der_6 != nil {
			return nil, fmt.Errorf("encoding ulArgType: %w", tagErr_enc_der_6)
		}
		enc_der_6 = retagged_enc_der_6
		if derErr := ber.ValidateDEREncodedElement(enc_der_6); derErr != nil {
			return nil, fmt.Errorf("encoding ulArgType as DER: %w", derErr)
		}
		return enc_der_6, nil
	case ExtensionTypeChoiceRdArgType:
		if v.RdArgType == nil {
			return nil, fmt.Errorf("%w: choice ExtensionType: rdArgType is nil", ber.ErrInvalidValue)
		}
		enc_der_7, err := v.RdArgType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding rdArgType: %w", err)
		}
		retagged_enc_der_7, tagErr_enc_der_7 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_der_7)
		if tagErr_enc_der_7 != nil {
			return nil, fmt.Errorf("encoding rdArgType: %w", tagErr_enc_der_7)
		}
		enc_der_7 = retagged_enc_der_7
		if derErr := ber.ValidateDEREncodedElement(enc_der_7); derErr != nil {
			return nil, fmt.Errorf("encoding rdArgType as DER: %w", derErr)
		}
		return enc_der_7, nil
	case ExtensionTypeChoiceSaiArgType:
		if v.SaiArgType == nil {
			return nil, fmt.Errorf("%w: choice ExtensionType: saiArgType is nil", ber.ErrInvalidValue)
		}
		enc_der_8, err := v.SaiArgType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding saiArgType: %w", err)
		}
		retagged_enc_der_8, tagErr_enc_der_8 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_der_8)
		if tagErr_enc_der_8 != nil {
			return nil, fmt.Errorf("encoding saiArgType: %w", tagErr_enc_der_8)
		}
		enc_der_8 = retagged_enc_der_8
		if derErr := ber.ValidateDEREncodedElement(enc_der_8); derErr != nil {
			return nil, fmt.Errorf("encoding saiArgType as DER: %w", derErr)
		}
		return enc_der_8, nil
	case ExtensionTypeChoiceSaiResType:
		if v.SaiResType == nil {
			return nil, fmt.Errorf("%w: choice ExtensionType: saiResType is nil", ber.ErrInvalidValue)
		}
		enc_der_9, err := v.SaiResType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding saiResType: %w", err)
		}
		retagged_enc_der_9, tagErr_enc_der_9 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_der_9)
		if tagErr_enc_der_9 != nil {
			return nil, fmt.Errorf("encoding saiResType: %w", tagErr_enc_der_9)
		}
		enc_der_9 = retagged_enc_der_9
		if derErr := ber.ValidateDEREncodedElement(enc_der_9); derErr != nil {
			return nil, fmt.Errorf("encoding saiResType as DER: %w", derErr)
		}
		return enc_der_9, nil
	case ExtensionTypeChoiceAtiArgType:
		if v.AtiArgType == nil {
			return nil, fmt.Errorf("%w: choice ExtensionType: atiArgType is nil", ber.ErrInvalidValue)
		}
		enc_der_10, err := v.AtiArgType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding atiArgType: %w", err)
		}
		retagged_enc_der_10, tagErr_enc_der_10 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_der_10)
		if tagErr_enc_der_10 != nil {
			return nil, fmt.Errorf("encoding atiArgType: %w", tagErr_enc_der_10)
		}
		enc_der_10 = retagged_enc_der_10
		if derErr := ber.ValidateDEREncodedElement(enc_der_10); derErr != nil {
			return nil, fmt.Errorf("encoding atiArgType as DER: %w", derErr)
		}
		return enc_der_10, nil
	case ExtensionTypeChoiceAtiResType:
		if v.AtiResType == nil {
			return nil, fmt.Errorf("%w: choice ExtensionType: atiResType is nil", ber.ErrInvalidValue)
		}
		enc_der_11, err := v.AtiResType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding atiResType: %w", err)
		}
		retagged_enc_der_11, tagErr_enc_der_11 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_der_11)
		if tagErr_enc_der_11 != nil {
			return nil, fmt.Errorf("encoding atiResType: %w", tagErr_enc_der_11)
		}
		enc_der_11 = retagged_enc_der_11
		if derErr := ber.ValidateDEREncodedElement(enc_der_11); derErr != nil {
			return nil, fmt.Errorf("encoding atiResType as DER: %w", derErr)
		}
		return enc_der_11, nil
	case ExtensionTypeChoiceExtAtiArgType:
		enc_der_12, err := MarshalDERExtAtiArgType(v.ExtAtiArgType)
		if err != nil {
			return nil, fmt.Errorf("encoding extAtiArgType: %w", err)
		}
		if len((v.ExtAtiArgType).Values) < 1 || len((v.ExtAtiArgType).Values) > 50 {
			if constraintErr := ber.CheckEncodedLength(nil, "extAtiArgType", "SIZE (1..50)", len((v.ExtAtiArgType).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_12, tagErr_enc_der_12 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_der_12)
		if tagErr_enc_der_12 != nil {
			return nil, fmt.Errorf("encoding extAtiArgType: %w", tagErr_enc_der_12)
		}
		enc_der_12 = retagged_enc_der_12
		if derErr := ber.ValidateDEREncodedElement(enc_der_12); derErr != nil {
			return nil, fmt.Errorf("encoding extAtiArgType as DER: %w", derErr)
		}
		return enc_der_12, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtensionType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtensionType from BER/DER format.
func (v *ExtensionType) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtensionType destination is nil", ber.ErrInvalidValue)
	}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtensionType{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for ExtensionType CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for ExtensionType: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding ExtensionType CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "ExtensionType", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceIsdArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding isdArgType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERIsdArgType(reconstructed, ber.ChildDecodeOptions(opts, "isdArgType")...)
		if unmErr != nil {
			return fmt.Errorf("decoding isdArgType: %w", unmErr)
		}
		v.IsdArgType = dec
		if len((v.IsdArgType).Values) < 1 || len((v.IsdArgType).Values) > 50 {
			if constraintErr := ber.CheckDecodedLength(opts, "isdArgType", "SIZE (1..50)", len((v.IsdArgType).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceIsdResType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding isdResType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERIsdResType(reconstructed, ber.ChildDecodeOptions(opts, "isdResType")...)
		if unmErr != nil {
			return fmt.Errorf("decoding isdResType: %w", unmErr)
		}
		v.IsdResType = dec
		if len((v.IsdResType).Values) < 1 || len((v.IsdResType).Values) > 50 {
			if constraintErr := ber.CheckDecodedLength(opts, "isdResType", "SIZE (1..50)", len((v.IsdResType).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceDsdArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding dsdArgType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERDsdArgType(reconstructed, ber.ChildDecodeOptions(opts, "dsdArgType")...)
		if unmErr != nil {
			return fmt.Errorf("decoding dsdArgType: %w", unmErr)
		}
		v.DsdArgType = dec
		if len((v.DsdArgType).Values) < 1 || len((v.DsdArgType).Values) > 50 {
			if constraintErr := ber.CheckDecodedLength(opts, "dsdArgType", "SIZE (1..50)", len((v.DsdArgType).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceSriArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding sriArgType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERSRIArgType(reconstructed, ber.ChildDecodeOptions(opts, "sriArgType")...)
		if unmErr != nil {
			return fmt.Errorf("decoding sriArgType: %w", unmErr)
		}
		v.SriArgType = dec
		if len((v.SriArgType).Values) < 1 || len((v.SriArgType).Values) > 50 {
			if constraintErr := ber.CheckDecodedLength(opts, "sriArgType", "SIZE (1..50)", len((v.SriArgType).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceSriResType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding sriResType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERSRIResType(reconstructed, ber.ChildDecodeOptions(opts, "sriResType")...)
		if unmErr != nil {
			return fmt.Errorf("decoding sriResType: %w", unmErr)
		}
		v.SriResType = dec
		if len((v.SriResType).Values) < 1 || len((v.SriResType).Values) > 50 {
			if constraintErr := ber.CheckDecodedLength(opts, "sriResType", "SIZE (1..50)", len((v.SriResType).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoicePrnArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding prnArgType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERPrnArgType(reconstructed, ber.ChildDecodeOptions(opts, "prnArgType")...)
		if unmErr != nil {
			return fmt.Errorf("decoding prnArgType: %w", unmErr)
		}
		v.PrnArgType = dec
		if len((v.PrnArgType).Values) < 1 || len((v.PrnArgType).Values) > 50 {
			if constraintErr := ber.CheckDecodedLength(opts, "prnArgType", "SIZE (1..50)", len((v.PrnArgType).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceUlArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding ulArgType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERUlArgType(reconstructed, ber.ChildDecodeOptions(opts, "ulArgType")...)
		if unmErr != nil {
			return fmt.Errorf("decoding ulArgType: %w", unmErr)
		}
		v.UlArgType = dec
		if len((v.UlArgType).Values) < 1 || len((v.UlArgType).Values) > 50 {
			if constraintErr := ber.CheckDecodedLength(opts, "ulArgType", "SIZE (1..50)", len((v.UlArgType).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceRdArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding rdArgType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec RdArgType
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding rdArgType: %w", unmErr)
		}
		v.RdArgType = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceSaiArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding saiArgType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec SaiArgType
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding saiArgType: %w", unmErr)
		}
		v.SaiArgType = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceSaiResType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding saiResType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec SaiResType
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding saiResType: %w", unmErr)
		}
		v.SaiResType = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceAtiArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding atiArgType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec AtiArgType
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding atiArgType: %w", unmErr)
		}
		v.AtiArgType = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceAtiResType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding atiResType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec AtiResType
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding atiResType: %w", unmErr)
		}
		v.AtiResType = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 && peekTag.Constructed == true {
		v.Choice = ExtensionTypeChoiceExtAtiArgType
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding extAtiArgType: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERExtAtiArgType(reconstructed, ber.ChildDecodeOptions(opts, "extAtiArgType")...)
		if unmErr != nil {
			return fmt.Errorf("decoding extAtiArgType: %w", unmErr)
		}
		v.ExtAtiArgType = dec
		if len((v.ExtAtiArgType).Values) < 1 || len((v.ExtAtiArgType).Values) > 50 {
			if constraintErr := ber.CheckDecodedLength(opts, "extAtiArgType", "SIZE (1..50)", len((v.ExtAtiArgType).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for ExtensionType CHOICE", peekTag)
	}
	return nil
}

// MarshalBERIsdArgType encodes a IsdArgType list to BER.
func MarshalBERIsdArgType(collection *IsdArgType, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERIsdArgType(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERIsdArgType(collection *IsdArgType, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(opts, "IsdArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERIsdArgType encodes a IsdArgType list to DER.
func MarshalDERIsdArgType(collection *IsdArgType) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(nil, "IsdArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IsdArgType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERIsdArgType decodes a IsdArgType list from BER.
func UnmarshalBERIsdArgType(data []byte, opts ...ber.DecodeOption) (*IsdArgType, error) {
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding IsdArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "IsdArgType", Cause: ber.ErrExtraData}
	}
	var result []IsdArgData
	offset := 0
	for offset < len(content) {
		var elem IsdArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		if unmErr := elem.UnmarshalBER(content[offset:offset+n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedLength(opts, "IsdArgType", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &IsdArgType{Values: result}
	if ber.ConstraintToleranceEnabled(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERIsdArgType(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes IsdArgData to BER format.
func (v *IsdArgData) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IsdArgData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IsdArgData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
		children = append(children, enc_privatefeaturecode...)
	}
	if v.PrivateFeatureData != nil {
		enc_privatefeaturedata, err := v.PrivateFeatureData.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IsdArgData to DER format.
func (v *IsdArgData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IsdArgData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
		children = append(children, enc_privatefeaturecode...)
	}
	if v.PrivateFeatureData != nil {
		enc_privatefeaturedata, err := v.PrivateFeatureData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding privateFeatureData: %w", err)
		}
		children = append(children, enc_privatefeaturedata...)
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
		return nil, fmt.Errorf("encoding IsdArgData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IsdArgData from BER/DER format.
func (v *IsdArgData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IsdArgData destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IsdArgData{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_privatefeaturecode, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				if decodedTag_privatefeaturecode.Class != tag.ClassContextSpecific || decodedTag_privatefeaturecode.Number != 1 {
					return fmt.Errorf("decoding privateFeatureCode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privatefeaturecode)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				if offset < 0 || offset >
					len(content) || n_privatefeaturecode < 0 || n_privatefeaturecode >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privatefeaturecode
				if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode privateFeatureData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) {
				// Decode nested CHOICE (PrivateFeatureData)
				_, n_privatefeaturedata, _, tlvErr_privatefeaturedata := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_privatefeaturedata != nil {
					return fmt.Errorf("decoding privateFeatureData: %w", tlvErr_privatefeaturedata)
				}
				var dec_privatefeaturedata PrivateFeatureData
				if offset < 0 || offset >
					len(content) || n_privatefeaturedata < 0 || n_privatefeaturedata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_privatefeaturedata.UnmarshalBER(content[offset:offset+n_privatefeaturedata], ber.ChildDecodeOptions(opts, "privatefeaturedata")...); unmErr != nil {
					return fmt.Errorf("decoding privateFeatureData: %w", unmErr)
				}
				v.PrivateFeatureData = &dec_privatefeaturedata
				if offset < 0 || offset >
					len(content) || n_privatefeaturedata < 0 || n_privatefeaturedata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privatefeaturedata
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "IsdArgData", Cause: extErr_}
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

// MarshalBER encodes PrivateFeatureData to BER format.
func (v *PrivateFeatureData) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrivateFeatureData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PrivateFeatureData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case PrivateFeatureDataChoiceSubscriptionTypeInfo:
		if v.SubscriptionTypeInfo == nil {
			return nil, fmt.Errorf("%w: choice PrivateFeatureData: subscriptionTypeInfo is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.SubscriptionTypeInfo.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding subscriptionTypeInfo: %w", err)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding subscriptionTypeInfo: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case PrivateFeatureDataChoiceOickInfo:
		if v.OickInfo == nil {
			return nil, fmt.Errorf("%w: choice PrivateFeatureData: oickInfo is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.OickInfo.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding oickInfo: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding oickInfo: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PrivateFeatureData", v.Choice)
	}
}

// MarshalDER encodes PrivateFeatureData to DER format.
func (v *PrivateFeatureData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrivateFeatureData receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case PrivateFeatureDataChoiceSubscriptionTypeInfo:
		if v.SubscriptionTypeInfo == nil {
			return nil, fmt.Errorf("%w: choice PrivateFeatureData: subscriptionTypeInfo is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.SubscriptionTypeInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding subscriptionTypeInfo: %w", err)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding subscriptionTypeInfo: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding subscriptionTypeInfo as DER: %w", derErr)
		}
		return enc_der_0, nil
	case PrivateFeatureDataChoiceOickInfo:
		if v.OickInfo == nil {
			return nil, fmt.Errorf("%w: choice PrivateFeatureData: oickInfo is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.OickInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding oickInfo: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding oickInfo: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding oickInfo as DER: %w", derErr)
		}
		return enc_der_1, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PrivateFeatureData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrivateFeatureData from BER/DER format.
func (v *PrivateFeatureData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PrivateFeatureData destination is nil", ber.ErrInvalidValue)
	}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PrivateFeatureData{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for PrivateFeatureData CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PrivateFeatureData: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding PrivateFeatureData CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PrivateFeatureData", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = PrivateFeatureDataChoiceSubscriptionTypeInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding subscriptionTypeInfo: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec SubscriptionTypeInfo
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding subscriptionTypeInfo: %w", unmErr)
		}
		v.SubscriptionTypeInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 && peekTag.Constructed == true {
		v.Choice = PrivateFeatureDataChoiceOickInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding oickInfo: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec OickInfo
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding oickInfo: %w", unmErr)
		}
		v.OickInfo = &dec
	} else {
		return fmt.Errorf("unknown tag %s for PrivateFeatureData CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes OickInfo to BER format.
func (v *OickInfo) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OickInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *OickInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 5 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
	}
	children = append(children, enc_ssstatus...)
	if len(v.InCategoryKey) < 1 || len(v.InCategoryKey) > 3 {
		if constraintErr := ber.CheckEncodedLength(opts, "inCategoryKey", "SIZE (1..3)", len(v.InCategoryKey)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_incategorykey, encodeErr_enc_incategorykey := ber.EncodeOctetString([]byte(v.InCategoryKey))
	if encodeErr_enc_incategorykey != nil {
		return nil, fmt.Errorf("encoding inCategoryKey: %w", encodeErr_enc_incategorykey)
	}
	children = append(children, enc_incategorykey...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes OickInfo to DER format.
func (v *OickInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: OickInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 5 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
	}
	children = append(children, enc_ssstatus...)
	if len(v.InCategoryKey) < 1 || len(v.InCategoryKey) > 3 {
		if constraintErr := ber.CheckEncodedLength(nil, "inCategoryKey", "SIZE (1..3)", len(v.InCategoryKey)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_incategorykey, encodeErr_enc_incategorykey := ber.EncodeOctetString([]byte(v.InCategoryKey))
	if encodeErr_enc_incategorykey != nil {
		return nil, fmt.Errorf("encoding inCategoryKey: %w", encodeErr_enc_incategorykey)
	}
	children = append(children, enc_incategorykey...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding OickInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes OickInfo from BER/DER format.
func (v *OickInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: OickInfo destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = OickInfo{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
	val_ssstatus, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ss-Status: %w", err)
	}
	v.SsStatus = ExtSSStatus5(val_ssstatus)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 5 {
		if constraintErr := ber.CheckDecodedLength(opts, "ss-Status", "SIZE (1..5)", len(v.SsStatus)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode inCategoryKey
	if offset >= len(content) {
		return fmt.Errorf("missing required field inCategoryKey")
	}
	val_incategorykey, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding inCategoryKey: %w", err)
	}
	v.InCategoryKey = INCategoryKey(val_incategorykey)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.InCategoryKey) < 1 || len(v.InCategoryKey) > 3 {
		if constraintErr := ber.CheckDecodedLength(opts, "inCategoryKey", "SIZE (1..3)", len(v.InCategoryKey)); constraintErr != nil {
			return constraintErr
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "OickInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SubscriptionTypeInfo to BER format.
func (v *SubscriptionTypeInfo) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriptionTypeInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SubscriptionTypeInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SubscriptionType) < 1 || len(v.SubscriptionType) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "subscriptionType", "SIZE (1)", len(v.SubscriptionType)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_subscriptiontype, encodeErr_enc_subscriptiontype := ber.EncodeOctetString([]byte(v.SubscriptionType))
	if encodeErr_enc_subscriptiontype != nil {
		return nil, fmt.Errorf("encoding subscriptionType: %w", encodeErr_enc_subscriptiontype)
	}
	children = append(children, enc_subscriptiontype...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SubscriptionTypeInfo to DER format.
func (v *SubscriptionTypeInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriptionTypeInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SubscriptionType) < 1 || len(v.SubscriptionType) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "subscriptionType", "SIZE (1)", len(v.SubscriptionType)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_subscriptiontype, encodeErr_enc_subscriptiontype := ber.EncodeOctetString([]byte(v.SubscriptionType))
	if encodeErr_enc_subscriptiontype != nil {
		return nil, fmt.Errorf("encoding subscriptionType: %w", encodeErr_enc_subscriptiontype)
	}
	children = append(children, enc_subscriptiontype...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SubscriptionTypeInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SubscriptionTypeInfo from BER/DER format.
func (v *SubscriptionTypeInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SubscriptionTypeInfo destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SubscriptionTypeInfo{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
	val_subscriptiontype, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding subscriptionType: %w", err)
	}
	v.SubscriptionType = SubscriptionType(val_subscriptiontype)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SubscriptionType) < 1 || len(v.SubscriptionType) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "subscriptionType", "SIZE (1)", len(v.SubscriptionType)); constraintErr != nil {
			return constraintErr
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SubscriptionTypeInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERIsdResType encodes a IsdResType list to BER.
func MarshalBERIsdResType(collection *IsdResType, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERIsdResType(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERIsdResType(collection *IsdResType, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(opts, "IsdResType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERIsdResType encodes a IsdResType list to DER.
func MarshalDERIsdResType(collection *IsdResType) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(nil, "IsdResType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding IsdResType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERIsdResType decodes a IsdResType list from BER.
func UnmarshalBERIsdResType(data []byte, opts ...ber.DecodeOption) (*IsdResType, error) {
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding IsdResType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "IsdResType", Cause: ber.ErrExtraData}
	}
	var result []IsdResData
	offset := 0
	for offset < len(content) {
		var elem IsdResData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		if unmErr := elem.UnmarshalBER(content[offset:offset+n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedLength(opts, "IsdResType", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &IsdResType{Values: result}
	if ber.ConstraintToleranceEnabled(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERIsdResType(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes IsdResData to BER format.
func (v *IsdResData) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IsdResData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *IsdResData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SupportedPrivateFeature != nil {
		if len(*v.SupportedPrivateFeature) < 1 || len(*v.SupportedPrivateFeature) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "supportedPrivateFeature", "SIZE (1)", len(*v.SupportedPrivateFeature)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedprivatefeature, encodeErr_enc_supportedprivatefeature := ber.EncodeOctetString([]byte(*v.SupportedPrivateFeature))
		if encodeErr_enc_supportedprivatefeature != nil {
			return nil, fmt.Errorf("encoding supportedPrivateFeature: %w", encodeErr_enc_supportedprivatefeature)
		}
		retagged_enc_supportedprivatefeature, tagErr_enc_supportedprivatefeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_supportedprivatefeature)
		if tagErr_enc_supportedprivatefeature != nil {
			return nil, fmt.Errorf("encoding supportedPrivateFeature: %w", tagErr_enc_supportedprivatefeature)
		}
		enc_supportedprivatefeature = retagged_enc_supportedprivatefeature
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes IsdResData to DER format.
func (v *IsdResData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: IsdResData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SupportedPrivateFeature != nil {
		if len(*v.SupportedPrivateFeature) < 1 || len(*v.SupportedPrivateFeature) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "supportedPrivateFeature", "SIZE (1)", len(*v.SupportedPrivateFeature)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_supportedprivatefeature, encodeErr_enc_supportedprivatefeature := ber.EncodeOctetString([]byte(*v.SupportedPrivateFeature))
		if encodeErr_enc_supportedprivatefeature != nil {
			return nil, fmt.Errorf("encoding supportedPrivateFeature: %w", encodeErr_enc_supportedprivatefeature)
		}
		retagged_enc_supportedprivatefeature, tagErr_enc_supportedprivatefeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_supportedprivatefeature)
		if tagErr_enc_supportedprivatefeature != nil {
			return nil, fmt.Errorf("encoding supportedPrivateFeature: %w", tagErr_enc_supportedprivatefeature)
		}
		enc_supportedprivatefeature = retagged_enc_supportedprivatefeature
		children = append(children, enc_supportedprivatefeature...)
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
		return nil, fmt.Errorf("encoding IsdResData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes IsdResData from BER/DER format.
func (v *IsdResData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: IsdResData destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = IsdResData{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_supportedprivatefeature, n_supportedprivatefeature, rawVal_supportedprivatefeature, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding supportedPrivateFeature: %w", err)
				}
				if decodedTag_supportedprivatefeature.Class != tag.ClassContextSpecific || decodedTag_supportedprivatefeature.Number != 1 {
					return fmt.Errorf("decoding supportedPrivateFeature: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_supportedprivatefeature)
				}
				tmp_supportedprivatefeature := PrivateFeatureCode(rawVal_supportedprivatefeature)
				v.SupportedPrivateFeature = &tmp_supportedprivatefeature
				if offset < 0 || offset >
					len(content) || n_supportedprivatefeature < 0 || n_supportedprivatefeature >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_supportedprivatefeature
				if len(*v.SupportedPrivateFeature) < 1 || len(*v.SupportedPrivateFeature) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "supportedPrivateFeature", "SIZE (1)", len(*v.SupportedPrivateFeature)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "IsdResData", Cause: extErr_}
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

// MarshalBERDsdArgType encodes a DsdArgType list to BER.
func MarshalBERDsdArgType(collection *DsdArgType, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERDsdArgType(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERDsdArgType(collection *DsdArgType, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(opts, "DsdArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERDsdArgType encodes a DsdArgType list to DER.
func MarshalDERDsdArgType(collection *DsdArgType) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(nil, "DsdArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DsdArgType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERDsdArgType decodes a DsdArgType list from BER.
func UnmarshalBERDsdArgType(data []byte, opts ...ber.DecodeOption) (*DsdArgType, error) {
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding DsdArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "DsdArgType", Cause: ber.ErrExtraData}
	}
	var result []DsdArgData
	offset := 0
	for offset < len(content) {
		var elem DsdArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		if unmErr := elem.UnmarshalBER(content[offset:offset+n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedLength(opts, "DsdArgType", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &DsdArgType{Values: result}
	if ber.ConstraintToleranceEnabled(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERDsdArgType(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes DsdArgData to BER format.
func (v *DsdArgData) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DsdArgData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *DsdArgData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.PrivateFeatureWithdraw) < 1 || len(v.PrivateFeatureWithdraw) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "privateFeatureWithdraw", "SIZE (1)", len(v.PrivateFeatureWithdraw)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_privatefeaturewithdraw, encodeErr_enc_privatefeaturewithdraw := ber.EncodeOctetString([]byte(v.PrivateFeatureWithdraw))
	if encodeErr_enc_privatefeaturewithdraw != nil {
		return nil, fmt.Errorf("encoding privateFeatureWithdraw: %w", encodeErr_enc_privatefeaturewithdraw)
	}
	children = append(children, enc_privatefeaturewithdraw...)
	return ber.EncodeSequence(children)
}

// MarshalDER encodes DsdArgData to DER format.
func (v *DsdArgData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DsdArgData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.PrivateFeatureWithdraw) < 1 || len(v.PrivateFeatureWithdraw) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "privateFeatureWithdraw", "SIZE (1)", len(v.PrivateFeatureWithdraw)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_privatefeaturewithdraw, encodeErr_enc_privatefeaturewithdraw := ber.EncodeOctetString([]byte(v.PrivateFeatureWithdraw))
	if encodeErr_enc_privatefeaturewithdraw != nil {
		return nil, fmt.Errorf("encoding privateFeatureWithdraw: %w", encodeErr_enc_privatefeaturewithdraw)
	}
	children = append(children, enc_privatefeaturewithdraw...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding DsdArgData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes DsdArgData from BER/DER format.
func (v *DsdArgData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: DsdArgData destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = DsdArgData{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
	val_privatefeaturewithdraw, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding privateFeatureWithdraw: %w", err)
	}
	v.PrivateFeatureWithdraw = PrivateFeatureCode(val_privatefeaturewithdraw)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.PrivateFeatureWithdraw) < 1 || len(v.PrivateFeatureWithdraw) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "privateFeatureWithdraw", "SIZE (1)", len(v.PrivateFeatureWithdraw)); constraintErr != nil {
			return constraintErr
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DsdArgData", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBERSRIArgType encodes a SRIArgType list to BER.
func MarshalBERSRIArgType(collection *SRIArgType, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERSRIArgType(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERSRIArgType(collection *SRIArgType, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(opts, "SRIArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERSRIArgType encodes a SRIArgType list to DER.
func MarshalDERSRIArgType(collection *SRIArgType) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(nil, "SRIArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SRIArgType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERSRIArgType decodes a SRIArgType list from BER.
func UnmarshalBERSRIArgType(data []byte, opts ...ber.DecodeOption) (*SRIArgType, error) {
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding SRIArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SRIArgType", Cause: ber.ErrExtraData}
	}
	var result []SriArgData
	offset := 0
	for offset < len(content) {
		var elem SriArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		if unmErr := elem.UnmarshalBER(content[offset:offset+n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedLength(opts, "SRIArgType", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SRIArgType{Values: result}
	if ber.ConstraintToleranceEnabled(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERSRIArgType(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes SriArgData to BER format.
func (v *SriArgData) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SriArgData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SriArgData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
		children = append(children, enc_privatefeaturecode...)
	}
	if v.ExtraNetworkInfo != nil {
		enc_extranetworkinfo, err := v.ExtraNetworkInfo.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding extraNetworkInfo: %w", err)
		}
		retagged_enc_extranetworkinfo, tagErr_enc_extranetworkinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_extranetworkinfo)
		if tagErr_enc_extranetworkinfo != nil {
			return nil, fmt.Errorf("encoding extraNetworkInfo: %w", tagErr_enc_extranetworkinfo)
		}
		enc_extranetworkinfo = retagged_enc_extranetworkinfo
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SriArgData to DER format.
func (v *SriArgData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SriArgData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
		children = append(children, enc_privatefeaturecode...)
	}
	if v.ExtraNetworkInfo != nil {
		enc_extranetworkinfo, err := v.ExtraNetworkInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extraNetworkInfo: %w", err)
		}
		retagged_enc_extranetworkinfo, tagErr_enc_extranetworkinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_extranetworkinfo)
		if tagErr_enc_extranetworkinfo != nil {
			return nil, fmt.Errorf("encoding extraNetworkInfo: %w", tagErr_enc_extranetworkinfo)
		}
		enc_extranetworkinfo = retagged_enc_extranetworkinfo
		children = append(children, enc_extranetworkinfo...)
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
		return nil, fmt.Errorf("encoding SriArgData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SriArgData from BER/DER format.
func (v *SriArgData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SriArgData destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SriArgData{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_privatefeaturecode, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				if decodedTag_privatefeaturecode.Class != tag.ClassContextSpecific || decodedTag_privatefeaturecode.Number != 1 {
					return fmt.Errorf("decoding privateFeatureCode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privatefeaturecode)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				if offset < 0 || offset >
					len(content) || n_privatefeaturecode < 0 || n_privatefeaturecode >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privatefeaturecode
				if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extraNetworkInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_extranetworkinfo, n_extranetworkinfo, rawVal_extranetworkinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extraNetworkInfo: %w", err)
				}
				if decodedTag_extranetworkinfo.Class != tag.ClassContextSpecific || decodedTag_extranetworkinfo.Number != 2 || decodedTag_extranetworkinfo.Constructed != true {
					return fmt.Errorf("decoding extraNetworkInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extranetworkinfo)
				}
				reconstructed_extranetworkinfo, reconstructionErr_extranetworkinfo := ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 1, Constructed: true}, rawVal_extranetworkinfo)
				if reconstructionErr_extranetworkinfo != nil {
					return fmt.Errorf("decoding extraNetworkInfo: %w", reconstructionErr_extranetworkinfo)
				}
				var dec_extranetworkinfo ExtraSignalInfo
				if unmErr := dec_extranetworkinfo.UnmarshalBER(reconstructed_extranetworkinfo, ber.ChildDecodeOptions(opts, "extranetworkinfo")...); unmErr != nil {
					return fmt.Errorf("decoding extraNetworkInfo: %w", unmErr)
				}
				v.ExtraNetworkInfo = &dec_extranetworkinfo
				if offset < 0 || offset >
					len(content) || n_extranetworkinfo < 0 || n_extranetworkinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extranetworkinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SriArgData", Cause: extErr_}
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

// MarshalBERSRIResType encodes a SRIResType list to BER.
func MarshalBERSRIResType(collection *SRIResType, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERSRIResType(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERSRIResType(collection *SRIResType, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(opts, "SRIResType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERSRIResType encodes a SRIResType list to DER.
func MarshalDERSRIResType(collection *SRIResType) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(nil, "SRIResType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SRIResType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERSRIResType decodes a SRIResType list from BER.
func UnmarshalBERSRIResType(data []byte, opts ...ber.DecodeOption) (*SRIResType, error) {
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding SRIResType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SRIResType", Cause: ber.ErrExtraData}
	}
	var result []SriResData
	offset := 0
	for offset < len(content) {
		var elem SriResData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		if unmErr := elem.UnmarshalBER(content[offset:offset+n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedLength(opts, "SRIResType", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SRIResType{Values: result}
	if ber.ConstraintToleranceEnabled(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERSRIResType(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes SriResData to BER format.
func (v *SriResData) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SriResData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SriResData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
		children = append(children, enc_privatefeaturecode...)
	}
	if v.InCategoryKey != nil {
		if len(*v.InCategoryKey) < 1 || len(*v.InCategoryKey) > 3 {
			if constraintErr := ber.CheckEncodedLength(opts, "inCategoryKey", "SIZE (1..3)", len(*v.InCategoryKey)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_incategorykey, encodeErr_enc_incategorykey := ber.EncodeOctetString([]byte(*v.InCategoryKey))
		if encodeErr_enc_incategorykey != nil {
			return nil, fmt.Errorf("encoding inCategoryKey: %w", encodeErr_enc_incategorykey)
		}
		retagged_enc_incategorykey, tagErr_enc_incategorykey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_incategorykey)
		if tagErr_enc_incategorykey != nil {
			return nil, fmt.Errorf("encoding inCategoryKey: %w", tagErr_enc_incategorykey)
		}
		enc_incategorykey = retagged_enc_incategorykey
		children = append(children, enc_incategorykey...)
	}
	if v.SubscriptionType != nil {
		if len(*v.SubscriptionType) < 1 || len(*v.SubscriptionType) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "subscriptionType", "SIZE (1)", len(*v.SubscriptionType)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_subscriptiontype, encodeErr_enc_subscriptiontype := ber.EncodeOctetString([]byte(*v.SubscriptionType))
		if encodeErr_enc_subscriptiontype != nil {
			return nil, fmt.Errorf("encoding subscriptionType: %w", encodeErr_enc_subscriptiontype)
		}
		retagged_enc_subscriptiontype, tagErr_enc_subscriptiontype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_subscriptiontype)
		if tagErr_enc_subscriptiontype != nil {
			return nil, fmt.Errorf("encoding subscriptionType: %w", tagErr_enc_subscriptiontype)
		}
		enc_subscriptiontype = retagged_enc_subscriptiontype
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SriResData to DER format.
func (v *SriResData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SriResData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
		children = append(children, enc_privatefeaturecode...)
	}
	if v.InCategoryKey != nil {
		if len(*v.InCategoryKey) < 1 || len(*v.InCategoryKey) > 3 {
			if constraintErr := ber.CheckEncodedLength(nil, "inCategoryKey", "SIZE (1..3)", len(*v.InCategoryKey)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_incategorykey, encodeErr_enc_incategorykey := ber.EncodeOctetString([]byte(*v.InCategoryKey))
		if encodeErr_enc_incategorykey != nil {
			return nil, fmt.Errorf("encoding inCategoryKey: %w", encodeErr_enc_incategorykey)
		}
		retagged_enc_incategorykey, tagErr_enc_incategorykey := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_incategorykey)
		if tagErr_enc_incategorykey != nil {
			return nil, fmt.Errorf("encoding inCategoryKey: %w", tagErr_enc_incategorykey)
		}
		enc_incategorykey = retagged_enc_incategorykey
		children = append(children, enc_incategorykey...)
	}
	if v.SubscriptionType != nil {
		if len(*v.SubscriptionType) < 1 || len(*v.SubscriptionType) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "subscriptionType", "SIZE (1)", len(*v.SubscriptionType)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_subscriptiontype, encodeErr_enc_subscriptiontype := ber.EncodeOctetString([]byte(*v.SubscriptionType))
		if encodeErr_enc_subscriptiontype != nil {
			return nil, fmt.Errorf("encoding subscriptionType: %w", encodeErr_enc_subscriptiontype)
		}
		retagged_enc_subscriptiontype, tagErr_enc_subscriptiontype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_subscriptiontype)
		if tagErr_enc_subscriptiontype != nil {
			return nil, fmt.Errorf("encoding subscriptionType: %w", tagErr_enc_subscriptiontype)
		}
		enc_subscriptiontype = retagged_enc_subscriptiontype
		children = append(children, enc_subscriptiontype...)
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
		return nil, fmt.Errorf("encoding SriResData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SriResData from BER/DER format.
func (v *SriResData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SriResData destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SriResData{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_privatefeaturecode, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				if decodedTag_privatefeaturecode.Class != tag.ClassContextSpecific || decodedTag_privatefeaturecode.Number != 1 {
					return fmt.Errorf("decoding privateFeatureCode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privatefeaturecode)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				if offset < 0 || offset >
					len(content) || n_privatefeaturecode < 0 || n_privatefeaturecode >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privatefeaturecode
				if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode inCategoryKey
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_incategorykey, n_incategorykey, rawVal_incategorykey, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding inCategoryKey: %w", err)
				}
				if decodedTag_incategorykey.Class != tag.ClassContextSpecific || decodedTag_incategorykey.Number != 2 {
					return fmt.Errorf("decoding inCategoryKey: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_incategorykey)
				}
				tmp_incategorykey := INCategoryKey(rawVal_incategorykey)
				v.InCategoryKey = &tmp_incategorykey
				if offset < 0 || offset >
					len(content) || n_incategorykey < 0 || n_incategorykey >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_incategorykey
				if len(*v.InCategoryKey) < 1 || len(*v.InCategoryKey) > 3 {
					if constraintErr := ber.CheckDecodedLength(opts, "inCategoryKey", "SIZE (1..3)", len(*v.InCategoryKey)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode subscriptionType
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_subscriptiontype, n_subscriptiontype, rawVal_subscriptiontype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding subscriptionType: %w", err)
				}
				if decodedTag_subscriptiontype.Class != tag.ClassContextSpecific || decodedTag_subscriptiontype.Number != 5 {
					return fmt.Errorf("decoding subscriptionType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_subscriptiontype)
				}
				tmp_subscriptiontype := SubscriptionType(rawVal_subscriptiontype)
				v.SubscriptionType = &tmp_subscriptiontype
				if offset < 0 || offset >
					len(content) || n_subscriptiontype < 0 || n_subscriptiontype >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_subscriptiontype
				if len(*v.SubscriptionType) < 1 || len(*v.SubscriptionType) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "subscriptionType", "SIZE (1)", len(*v.SubscriptionType)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SriResData", Cause: extErr_}
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

// MarshalBERPrnArgType encodes a PrnArgType list to BER.
func MarshalBERPrnArgType(collection *PrnArgType, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERPrnArgType(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERPrnArgType(collection *PrnArgType, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(opts, "PrnArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERPrnArgType encodes a PrnArgType list to DER.
func MarshalDERPrnArgType(collection *PrnArgType) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(nil, "PrnArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PrnArgType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERPrnArgType decodes a PrnArgType list from BER.
func UnmarshalBERPrnArgType(data []byte, opts ...ber.DecodeOption) (*PrnArgType, error) {
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding PrnArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "PrnArgType", Cause: ber.ErrExtraData}
	}
	var result []PrnArgData
	offset := 0
	for offset < len(content) {
		var elem PrnArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		if unmErr := elem.UnmarshalBER(content[offset:offset+n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedLength(opts, "PrnArgType", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &PrnArgType{Values: result}
	if ber.ConstraintToleranceEnabled(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERPrnArgType(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes PrnArgData to BER format.
func (v *PrnArgData) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrnArgData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PrnArgData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
		children = append(children, enc_privatefeaturecode...)
	}
	if v.ExtraNetworkInfo != nil {
		enc_extranetworkinfo, err := v.ExtraNetworkInfo.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding extraNetworkInfo: %w", err)
		}
		retagged_enc_extranetworkinfo, tagErr_enc_extranetworkinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_extranetworkinfo)
		if tagErr_enc_extranetworkinfo != nil {
			return nil, fmt.Errorf("encoding extraNetworkInfo: %w", tagErr_enc_extranetworkinfo)
		}
		enc_extranetworkinfo = retagged_enc_extranetworkinfo
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes PrnArgData to DER format.
func (v *PrnArgData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrnArgData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
		children = append(children, enc_privatefeaturecode...)
	}
	if v.ExtraNetworkInfo != nil {
		enc_extranetworkinfo, err := v.ExtraNetworkInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding extraNetworkInfo: %w", err)
		}
		retagged_enc_extranetworkinfo, tagErr_enc_extranetworkinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_extranetworkinfo)
		if tagErr_enc_extranetworkinfo != nil {
			return nil, fmt.Errorf("encoding extraNetworkInfo: %w", tagErr_enc_extranetworkinfo)
		}
		enc_extranetworkinfo = retagged_enc_extranetworkinfo
		children = append(children, enc_extranetworkinfo...)
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
		return nil, fmt.Errorf("encoding PrnArgData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrnArgData from BER/DER format.
func (v *PrnArgData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PrnArgData destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PrnArgData{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_privatefeaturecode, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				if decodedTag_privatefeaturecode.Class != tag.ClassContextSpecific || decodedTag_privatefeaturecode.Number != 1 {
					return fmt.Errorf("decoding privateFeatureCode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privatefeaturecode)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				if offset < 0 || offset >
					len(content) || n_privatefeaturecode < 0 || n_privatefeaturecode >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privatefeaturecode
				if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode extraNetworkInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_extranetworkinfo, n_extranetworkinfo, rawVal_extranetworkinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding extraNetworkInfo: %w", err)
				}
				if decodedTag_extranetworkinfo.Class != tag.ClassContextSpecific || decodedTag_extranetworkinfo.Number != 2 || decodedTag_extranetworkinfo.Constructed != true {
					return fmt.Errorf("decoding extraNetworkInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extranetworkinfo)
				}
				reconstructed_extranetworkinfo, reconstructionErr_extranetworkinfo := ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 1, Constructed: true}, rawVal_extranetworkinfo)
				if reconstructionErr_extranetworkinfo != nil {
					return fmt.Errorf("decoding extraNetworkInfo: %w", reconstructionErr_extranetworkinfo)
				}
				var dec_extranetworkinfo ExtraSignalInfo
				if unmErr := dec_extranetworkinfo.UnmarshalBER(reconstructed_extranetworkinfo, ber.ChildDecodeOptions(opts, "extranetworkinfo")...); unmErr != nil {
					return fmt.Errorf("decoding extraNetworkInfo: %w", unmErr)
				}
				v.ExtraNetworkInfo = &dec_extranetworkinfo
				if offset < 0 || offset >
					len(content) || n_extranetworkinfo < 0 || n_extranetworkinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_extranetworkinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "PrnArgData", Cause: extErr_}
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

// MarshalBERUlArgType encodes a UlArgType list to BER.
func MarshalBERUlArgType(collection *UlArgType, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERUlArgType(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERUlArgType(collection *UlArgType, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(opts, "UlArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERUlArgType encodes a UlArgType list to DER.
func MarshalDERUlArgType(collection *UlArgType) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(nil, "UlArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding UlArgType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERUlArgType decodes a UlArgType list from BER.
func UnmarshalBERUlArgType(data []byte, opts ...ber.DecodeOption) (*UlArgType, error) {
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding UlArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "UlArgType", Cause: ber.ErrExtraData}
	}
	var result []UlArgData
	offset := 0
	for offset < len(content) {
		var elem UlArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		if unmErr := elem.UnmarshalBER(content[offset:offset+n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedLength(opts, "UlArgType", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &UlArgType{Values: result}
	if ber.ConstraintToleranceEnabled(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERUlArgType(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes UlArgData to BER format.
func (v *UlArgData) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UlArgData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *UlArgData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
		children = append(children, enc_privatefeaturecode...)
	}
	if v.PrivateFeatureUlArgData != nil {
		enc_privatefeatureulargdata, err := v.PrivateFeatureUlArgData.MarshalBER(opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes UlArgData to DER format.
func (v *UlArgData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UlArgData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
		children = append(children, enc_privatefeaturecode...)
	}
	if v.PrivateFeatureUlArgData != nil {
		enc_privatefeatureulargdata, err := v.PrivateFeatureUlArgData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding privateFeatureUlArgData: %w", err)
		}
		children = append(children, enc_privatefeatureulargdata...)
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
		return nil, fmt.Errorf("encoding UlArgData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes UlArgData from BER/DER format.
func (v *UlArgData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: UlArgData destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = UlArgData{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_privatefeaturecode, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				if decodedTag_privatefeaturecode.Class != tag.ClassContextSpecific || decodedTag_privatefeaturecode.Number != 1 {
					return fmt.Errorf("decoding privateFeatureCode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privatefeaturecode)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				if offset < 0 || offset >
					len(content) || n_privatefeaturecode < 0 || n_privatefeaturecode >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privatefeaturecode
				if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode privateFeatureUlArgData
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				// Decode nested CHOICE (PrivateFeatureUlArgData)
				_, n_privatefeatureulargdata, _, tlvErr_privatefeatureulargdata := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_privatefeatureulargdata != nil {
					return fmt.Errorf("decoding privateFeatureUlArgData: %w", tlvErr_privatefeatureulargdata)
				}
				var dec_privatefeatureulargdata PrivateFeatureUlArgData
				if offset < 0 || offset >
					len(content) || n_privatefeatureulargdata < 0 || n_privatefeatureulargdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_privatefeatureulargdata.UnmarshalBER(content[offset:offset+n_privatefeatureulargdata], ber.ChildDecodeOptions(opts, "privatefeatureulargdata")...); unmErr != nil {
					return fmt.Errorf("decoding privateFeatureUlArgData: %w", unmErr)
				}
				v.PrivateFeatureUlArgData = &dec_privatefeatureulargdata
				if offset < 0 || offset >
					len(content) || n_privatefeatureulargdata < 0 || n_privatefeatureulargdata >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privatefeatureulargdata
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "UlArgData", Cause: extErr_}
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

// MarshalBER encodes PrivateFeatureUlArgData to BER format.
func (v *PrivateFeatureUlArgData) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrivateFeatureUlArgData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *PrivateFeatureUlArgData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case PrivateFeatureUlArgDataChoiceAdc:
		if v.Adc == nil {
			return nil, fmt.Errorf("%w: choice PrivateFeatureUlArgData: adc is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Adc))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding adc: %w", encodeErr_enc_0)
		}
		if len(*v.Adc) < 8 || len(*v.Adc) > 8 {
			if constraintErr := ber.CheckEncodedLength(opts, "adc", "SIZE (8)", len(*v.Adc)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding adc: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for PrivateFeatureUlArgData", v.Choice)
	}
}

// MarshalDER encodes PrivateFeatureUlArgData to DER format.
func (v *PrivateFeatureUlArgData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PrivateFeatureUlArgData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding PrivateFeatureUlArgData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes PrivateFeatureUlArgData from BER/DER format.
func (v *PrivateFeatureUlArgData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: PrivateFeatureUlArgData destination is nil", ber.ErrInvalidValue)
	}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = PrivateFeatureUlArgData{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for PrivateFeatureUlArgData CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for PrivateFeatureUlArgData: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding PrivateFeatureUlArgData CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "PrivateFeatureUlArgData", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = PrivateFeatureUlArgDataChoiceAdc
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding adc: %w", tlvErr)
		}
		tmp := IMEI5(rawVal)
		v.Adc = &tmp
		if len(*v.Adc) < 8 || len(*v.Adc) > 8 {
			if constraintErr := ber.CheckDecodedLength(opts, "adc", "SIZE (8)", len(*v.Adc)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for PrivateFeatureUlArgData CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ExtraSignalInfo to BER format.
func (v *ExtraSignalInfo) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtraSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ExtraSignalInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.ProtocolId) >= 1 && int64(v.ProtocolId) <= 20) {
		if constraintErr := ber.CheckEncodedValue(opts, "protocolId", "(1..20)", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeInteger(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	return ber.EncodeConstructed(tag.Tag{Class: tag.ClassPrivate, Number: 1, Constructed: true}, children)
}

// MarshalDER encodes ExtraSignalInfo to DER format.
func (v *ExtraSignalInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExtraSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.ProtocolId) >= 1 && int64(v.ProtocolId) <= 20) {
		if constraintErr := ber.CheckEncodedValue(nil, "protocolId", "(1..20)", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeInteger(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(nil, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, fmt.Errorf("encoding signalInfo: %w", encodeErr_enc_signalinfo)
	}
	children = append(children, enc_signalinfo...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	retagged_encoded, tagErr_encoded := ber.EncodeImplicitTagWithClass(tag.ClassPrivate, 1, encoded)
	if tagErr_encoded != nil {
		return nil, fmt.Errorf("encoding ExtraSignalInfo: %w", tagErr_encoded)
	}
	encoded = retagged_encoded
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtraSignalInfo as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ExtraSignalInfo from BER/DER format.
func (v *ExtraSignalInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ExtraSignalInfo destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ExtraSignalInfo{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
	decodedTag, content, total, err := ber.DecodeConstructedContent(data, opts...)
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
	val_protocolid, n, err := ber.DecodeInteger(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding protocolId: %w", err)
	}
	v.ProtocolId = ExtraProtocolId(val_protocolid)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if !(int64(v.ProtocolId) >= 1 && int64(v.ProtocolId) <= 20) {
		if constraintErr := ber.CheckDecodedValue(opts, "protocolId", "(1..20)", fmt.Sprint(int64(v.ProtocolId))); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field signalInfo")
	}
	val_signalinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding signalInfo: %w", err)
	}
	v.SignalInfo = SignalInfo5(val_signalinfo)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckDecodedLength(opts, "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return constraintErr
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExtraSignalInfo", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes SaiArgType to BER format.
func (v *SaiArgType) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SaiArgType receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SaiArgType) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeNull()
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.NoAuthenVectorsRequested != nil {
		enc_noauthenvectorsrequested := ber.EncodeNull()
		retagged_enc_noauthenvectorsrequested, tagErr_enc_noauthenvectorsrequested := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_noauthenvectorsrequested)
		if tagErr_enc_noauthenvectorsrequested != nil {
			return nil, fmt.Errorf("encoding noAuthenVectorsRequested: %w", tagErr_enc_noauthenvectorsrequested)
		}
		enc_noauthenvectorsrequested = retagged_enc_noauthenvectorsrequested
		children = append(children, enc_noauthenvectorsrequested...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SaiArgType to DER format.
func (v *SaiArgType) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SaiArgType receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeNull()
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.NoAuthenVectorsRequested != nil {
		enc_noauthenvectorsrequested := ber.EncodeNull()
		retagged_enc_noauthenvectorsrequested, tagErr_enc_noauthenvectorsrequested := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_noauthenvectorsrequested)
		if tagErr_enc_noauthenvectorsrequested != nil {
			return nil, fmt.Errorf("encoding noAuthenVectorsRequested: %w", tagErr_enc_noauthenvectorsrequested)
		}
		enc_noauthenvectorsrequested = retagged_enc_noauthenvectorsrequested
		children = append(children, enc_noauthenvectorsrequested...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SaiArgType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SaiArgType from BER/DER format.
func (v *SaiArgType) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SaiArgType destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SaiArgType{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 1 || decodedTag_msisdn.Constructed != false {
					return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				if len(rawVal_msisdn) != 0 {
					return fmt.Errorf("decoding msisdn: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_msisdn))
				}
				v.Msisdn = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
			}
		}
	}
	// Decode noAuthenVectorsRequested
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_noauthenvectorsrequested, n_noauthenvectorsrequested, rawVal_noauthenvectorsrequested, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding noAuthenVectorsRequested: %w", err)
				}
				if decodedTag_noauthenvectorsrequested.Class != tag.ClassContextSpecific || decodedTag_noauthenvectorsrequested.Number != 2 || decodedTag_noauthenvectorsrequested.Constructed != false {
					return fmt.Errorf("decoding noAuthenVectorsRequested: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_noauthenvectorsrequested)
				}
				if len(rawVal_noauthenvectorsrequested) != 0 {
					return fmt.Errorf("decoding noAuthenVectorsRequested: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_noauthenvectorsrequested))
				}
				v.NoAuthenVectorsRequested = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_noauthenvectorsrequested < 0 || n_noauthenvectorsrequested >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
func (v *SaiResType) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SaiResType receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SaiResType) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msIsdn", "SIZE (1..9)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.MsIsdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msIsdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msIsdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SaiResType to DER format.
func (v *SaiResType) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SaiResType receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "msIsdn", "SIZE (1..9)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.MsIsdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msIsdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msIsdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SaiResType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SaiResType from BER/DER format.
func (v *SaiResType) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SaiResType destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SaiResType{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msIsdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 1 {
					return fmt.Errorf("decoding msIsdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				tmp_msisdn := ISDNAddressString5(rawVal_msisdn)
				v.MsIsdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "msIsdn", "SIZE (1..9)", len(*v.MsIsdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SaiResType", Cause: ber.ErrExtraData}
	}
	return nil
}

// MarshalBER encodes AtiArgType to BER format.
func (v *AtiArgType) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AtiArgType receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AtiArgType) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.RequestedInfoType != nil {
		enc_requestedinfotype, err := v.RequestedInfoType.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding requestedInfoType: %w", err)
		}
		retagged_enc_requestedinfotype, tagErr_enc_requestedinfotype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_requestedinfotype)
		if tagErr_enc_requestedinfotype != nil {
			return nil, fmt.Errorf("encoding requestedInfoType: %w", tagErr_enc_requestedinfotype)
		}
		enc_requestedinfotype = retagged_enc_requestedinfotype
		children = append(children, enc_requestedinfotype...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AtiArgType to DER format.
func (v *AtiArgType) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AtiArgType receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.RequestedInfoType != nil {
		enc_requestedinfotype, err := v.RequestedInfoType.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding requestedInfoType: %w", err)
		}
		retagged_enc_requestedinfotype, tagErr_enc_requestedinfotype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_requestedinfotype)
		if tagErr_enc_requestedinfotype != nil {
			return nil, fmt.Errorf("encoding requestedInfoType: %w", tagErr_enc_requestedinfotype)
		}
		enc_requestedinfotype = retagged_enc_requestedinfotype
		children = append(children, enc_requestedinfotype...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AtiArgType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AtiArgType from BER/DER format.
func (v *AtiArgType) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AtiArgType destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AtiArgType{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_requestedinfotype, n_requestedinfotype, rawVal_requestedinfotype, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding requestedInfoType: %w", err)
				}
				if decodedTag_requestedinfotype.Class != tag.ClassContextSpecific || decodedTag_requestedinfotype.Number != 0 || decodedTag_requestedinfotype.Constructed != true {
					return fmt.Errorf("decoding requestedInfoType: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_requestedinfotype)
				}
				reconstructed_requestedinfotype, reconstructionErr_requestedinfotype := ber.EncodeSequence(rawVal_requestedinfotype)
				if reconstructionErr_requestedinfotype != nil {
					return fmt.Errorf("decoding requestedInfoType: %w", reconstructionErr_requestedinfotype)
				}
				var dec_requestedinfotype RequestedInfoType
				if unmErr := dec_requestedinfotype.UnmarshalBER(reconstructed_requestedinfotype, ber.ChildDecodeOptions(opts, "requestedinfotype")...); unmErr != nil {
					return fmt.Errorf("decoding requestedInfoType: %w", unmErr)
				}
				v.RequestedInfoType = &dec_requestedinfotype
				if offset < 0 || offset >
					len(content) || n_requestedinfotype < 0 || n_requestedinfotype >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
func (v *AtiResType) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AtiResType receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AtiResType) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ToBeDecided != nil {
		enc_tobedecided := ber.EncodeNull()
		retagged_enc_tobedecided, tagErr_enc_tobedecided := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tobedecided)
		if tagErr_enc_tobedecided != nil {
			return nil, fmt.Errorf("encoding toBeDecided: %w", tagErr_enc_tobedecided)
		}
		enc_tobedecided = retagged_enc_tobedecided
		children = append(children, enc_tobedecided...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AtiResType to DER format.
func (v *AtiResType) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AtiResType receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ToBeDecided != nil {
		enc_tobedecided := ber.EncodeNull()
		retagged_enc_tobedecided, tagErr_enc_tobedecided := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tobedecided)
		if tagErr_enc_tobedecided != nil {
			return nil, fmt.Errorf("encoding toBeDecided: %w", tagErr_enc_tobedecided)
		}
		enc_tobedecided = retagged_enc_tobedecided
		children = append(children, enc_tobedecided...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding AtiResType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AtiResType from BER/DER format.
func (v *AtiResType) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AtiResType destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AtiResType{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_tobedecided, n_tobedecided, rawVal_tobedecided, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding toBeDecided: %w", err)
				}
				if decodedTag_tobedecided.Class != tag.ClassContextSpecific || decodedTag_tobedecided.Number != 1 || decodedTag_tobedecided.Constructed != false {
					return fmt.Errorf("decoding toBeDecided: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tobedecided)
				}
				if len(rawVal_tobedecided) != 0 {
					return fmt.Errorf("decoding toBeDecided: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_tobedecided))
				}
				v.ToBeDecided = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_tobedecided < 0 || n_tobedecided >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
func (v *RdArgType) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RdArgType receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RdArgType) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ToBeDecidedOne != nil {
		enc_tobedecidedone := ber.EncodeNull()
		retagged_enc_tobedecidedone, tagErr_enc_tobedecidedone := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tobedecidedone)
		if tagErr_enc_tobedecidedone != nil {
			return nil, fmt.Errorf("encoding toBeDecidedOne: %w", tagErr_enc_tobedecidedone)
		}
		enc_tobedecidedone = retagged_enc_tobedecidedone
		children = append(children, enc_tobedecidedone...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes RdArgType to DER format.
func (v *RdArgType) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RdArgType receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ToBeDecidedOne != nil {
		enc_tobedecidedone := ber.EncodeNull()
		retagged_enc_tobedecidedone, tagErr_enc_tobedecidedone := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tobedecidedone)
		if tagErr_enc_tobedecidedone != nil {
			return nil, fmt.Errorf("encoding toBeDecidedOne: %w", tagErr_enc_tobedecidedone)
		}
		enc_tobedecidedone = retagged_enc_tobedecidedone
		children = append(children, enc_tobedecidedone...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RdArgType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RdArgType from BER/DER format.
func (v *RdArgType) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RdArgType destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RdArgType{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_tobedecidedone, n_tobedecidedone, rawVal_tobedecidedone, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding toBeDecidedOne: %w", err)
				}
				if decodedTag_tobedecidedone.Class != tag.ClassContextSpecific || decodedTag_tobedecidedone.Number != 1 || decodedTag_tobedecidedone.Constructed != false {
					return fmt.Errorf("decoding toBeDecidedOne: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_tobedecidedone)
				}
				if len(rawVal_tobedecidedone) != 0 {
					return fmt.Errorf("decoding toBeDecidedOne: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_tobedecidedone))
				}
				v.ToBeDecidedOne = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_tobedecidedone < 0 || n_tobedecidedone >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
func (v *RequestedInfoType) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RequestedInfoType receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RequestedInfoType) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SgsnNumber != nil {
		enc_sgsnnumber := ber.EncodeNull()
		retagged_enc_sgsnnumber, tagErr_enc_sgsnnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sgsnnumber)
		if tagErr_enc_sgsnnumber != nil {
			return nil, fmt.Errorf("encoding sgsnNumber: %w", tagErr_enc_sgsnnumber)
		}
		enc_sgsnnumber = retagged_enc_sgsnnumber
		children = append(children, enc_sgsnnumber...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDER encodes RequestedInfoType to DER format.
func (v *RequestedInfoType) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RequestedInfoType receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SgsnNumber != nil {
		enc_sgsnnumber := ber.EncodeNull()
		retagged_enc_sgsnnumber, tagErr_enc_sgsnnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sgsnnumber)
		if tagErr_enc_sgsnnumber != nil {
			return nil, fmt.Errorf("encoding sgsnNumber: %w", tagErr_enc_sgsnnumber)
		}
		enc_sgsnnumber = retagged_enc_sgsnnumber
		children = append(children, enc_sgsnnumber...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RequestedInfoType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RequestedInfoType from BER/DER format.
func (v *RequestedInfoType) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RequestedInfoType destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RequestedInfoType{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_sgsnnumber, n_sgsnnumber, rawVal_sgsnnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding sgsnNumber: %w", err)
				}
				if decodedTag_sgsnnumber.Class != tag.ClassContextSpecific || decodedTag_sgsnnumber.Number != 0 || decodedTag_sgsnnumber.Constructed != false {
					return fmt.Errorf("decoding sgsnNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sgsnnumber)
				}
				if len(rawVal_sgsnnumber) != 0 {
					return fmt.Errorf("decoding sgsnNumber: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_sgsnnumber))
				}
				v.SgsnNumber = &struct{}{}
				if offset < 0 || offset >
					len(content) || n_sgsnnumber < 0 || n_sgsnnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

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
func MarshalBERExtAtiArgType(collection *ExtAtiArgType, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERExtAtiArgType(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERExtAtiArgType(collection *ExtAtiArgType, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(opts, "ExtAtiArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERExtAtiArgType encodes a ExtAtiArgType list to DER.
func MarshalDERExtAtiArgType(collection *ExtAtiArgType) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedLength(nil, "ExtAtiArgType", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for _, elem := range list {
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding element: %w", err)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ExtAtiArgType as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERExtAtiArgType decodes a ExtAtiArgType list from BER.
func UnmarshalBERExtAtiArgType(data []byte, opts ...ber.DecodeOption) (*ExtAtiArgType, error) {
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding ExtAtiArgType: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ExtAtiArgType", Cause: ber.ErrExtraData}
	}
	var result []AtiArgData
	offset := 0
	for offset < len(content) {
		var elem AtiArgData
		_, n, _, tlvErr := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr != nil {
			return nil, fmt.Errorf("decoding element TLV: %w", tlvErr)
		}
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		if unmErr := elem.UnmarshalBER(content[offset:offset+n], ber.ChildDecodeOptions(opts, fmt.Sprintf("element[%d]", len(result)))...); unmErr != nil {
			return nil, fmt.Errorf("decoding element: %w", unmErr)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedLength(opts, "ExtAtiArgType", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &ExtAtiArgType{Values: result}
	if ber.ConstraintToleranceEnabled(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERExtAtiArgType(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes AtiArgData to BER format.
func (v *AtiArgData) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AtiArgData receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *AtiArgData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes AtiArgData to DER format.
func (v *AtiArgData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AtiArgData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.PrivateFeatureCode != nil {
		if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_privatefeaturecode, encodeErr_enc_privatefeaturecode := ber.EncodeOctetString([]byte(*v.PrivateFeatureCode))
		if encodeErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", encodeErr_enc_privatefeaturecode)
		}
		retagged_enc_privatefeaturecode, tagErr_enc_privatefeaturecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_privatefeaturecode)
		if tagErr_enc_privatefeaturecode != nil {
			return nil, fmt.Errorf("encoding privateFeatureCode: %w", tagErr_enc_privatefeaturecode)
		}
		enc_privatefeaturecode = retagged_enc_privatefeaturecode
		children = append(children, enc_privatefeaturecode...)
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
		return nil, fmt.Errorf("encoding AtiArgData as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes AtiArgData from BER/DER format.
func (v *AtiArgData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: AtiArgData destination is nil", ber.ErrInvalidValue)
	}
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = AtiArgData{}
	defer func() {
		if returnErr != nil || !ber.ConstraintToleranceEnabled(opts) {
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
				decodedTag_privatefeaturecode, n_privatefeaturecode, rawVal_privatefeaturecode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding privateFeatureCode: %w", err)
				}
				if decodedTag_privatefeaturecode.Class != tag.ClassContextSpecific || decodedTag_privatefeaturecode.Number != 1 {
					return fmt.Errorf("decoding privateFeatureCode: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_privatefeaturecode)
				}
				tmp_privatefeaturecode := PrivateFeatureCode(rawVal_privatefeaturecode)
				v.PrivateFeatureCode = &tmp_privatefeaturecode
				if offset < 0 || offset >
					len(content) || n_privatefeaturecode < 0 || n_privatefeaturecode >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_privatefeaturecode
				if len(*v.PrivateFeatureCode) < 1 || len(*v.PrivateFeatureCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "privateFeatureCode", "SIZE (1)", len(*v.PrivateFeatureCode)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "AtiArgData", Cause: extErr_}
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
