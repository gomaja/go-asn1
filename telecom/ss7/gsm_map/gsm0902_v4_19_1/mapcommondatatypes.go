// Code generated from ASN.1 module "MAP-CommonDataTypes". DO NOT EDIT.

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

const (

	// MaxAddressLength is the integer constant for maxAddressLength.
	MaxAddressLength int64 = 20

	// MaxISDNAddressLength is the integer constant for maxISDN-AddressLength.
	MaxISDNAddressLength int64 = 9

	// MaxISDNSubaddressLength is the integer constant for maxISDN-SubaddressLength.
	MaxISDNSubaddressLength int64 = 21

	// MaxSignalInfoLength is the integer constant for maxSignalInfoLength.
	MaxSignalInfoLength int64 = 200

	// MaxNumOfHLRId is the integer constant for maxNumOfHLR-Id.
	MaxNumOfHLRId int64 = 50

	// MaxNumOfBearerServices is the integer constant for maxNumOfBearerServices.
	MaxNumOfBearerServices int64 = 50

	// MaxNumOfTeleservices is the integer constant for maxNumOfTeleservices.
	MaxNumOfTeleservices int64 = 20

	// MaxNumOfBasicServices is the integer constant for maxNumOfBasicServices.
	MaxNumOfBasicServices int64 = 70

	// MaxNumOfBasicServiceGroups is the integer constant for maxNumOfBasicServiceGroups.
	MaxNumOfBasicServiceGroups int64 = 13
)

// TBCDSTRING represents the ASN.1 type TBCD-STRING (OCTET_STRING).
type TBCDSTRING = []byte

// AddressString represents the ASN.1 type AddressString (OCTET_STRING).
type AddressString = []byte

// ISDNAddressString represents the ASN.1 type ISDN-AddressString (OCTET_STRING).
type ISDNAddressString = AddressString

// ISDNSubaddressString represents the ASN.1 type ISDN-SubaddressString (OCTET_STRING).
type ISDNSubaddressString = []byte

// ExternalSignalInfo represents the ASN.1 type ExternalSignalInfo (SEQUENCE).
type ExternalSignalInfo struct {
	ProtocolId  ProtocolId `asn1:""`
	SignalInfo  SignalInfo `asn1:""`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SignalInfo represents the ASN.1 type SignalInfo (OCTET_STRING).
type SignalInfo = []byte

// ProtocolId represents the ASN.1 ENUMERATED type ProtocolId.
type ProtocolId int64

const (
	ProtocolIdGsm0408    ProtocolId = 1
	ProtocolIdGsm0806    ProtocolId = 2
	ProtocolIdGsmBSSMAP  ProtocolId = 3
	ProtocolIdEts3001021 ProtocolId = 4
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v ProtocolId) String() string {
	switch v {
	case ProtocolIdGsm0408:
		return "gsm-0408"
	case ProtocolIdGsm0806:
		return "gsm-0806"
	case ProtocolIdGsmBSSMAP:
		return "gsm-BSSMAP"
	case ProtocolIdEts3001021:
		return "ets-300102-1"
	default:
		return "unknown"
	}
}

// IMSI represents the ASN.1 type IMSI (OCTET_STRING).
type IMSI = TBCDSTRING

// TMSI represents the ASN.1 type TMSI (OCTET_STRING).
type TMSI = []byte

// SubscriberId choice constants.
const (
	SubscriberIdChoiceImsi = 1
	SubscriberIdChoiceTmsi = 2
)

// SubscriberId represents the ASN.1 CHOICE type SubscriberId.
type SubscriberId struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Imsi           *IMSI           `json:"Imsi,omitempty"`
	Tmsi           *TMSI           `json:"Tmsi,omitempty"`
}

// NewSubscriberIdImsi creates a SubscriberId with the imsi alternative.
func NewSubscriberIdImsi(v IMSI) SubscriberId {
	return SubscriberId{
		Choice: SubscriberIdChoiceImsi,
		Imsi:   &v,
	}
}

// NewSubscriberIdTmsi creates a SubscriberId with the tmsi alternative.
func NewSubscriberIdTmsi(v TMSI) SubscriberId {
	return SubscriberId{
		Choice: SubscriberIdChoiceTmsi,
		Tmsi:   &v,
	}
}

// IMEI represents the ASN.1 type IMEI (OCTET_STRING).
type IMEI = TBCDSTRING

// LocationInfo choice constants.
const (
	LocationInfoChoiceRoamingNumber = 1
	LocationInfoChoiceMscNumber     = 2
)

// LocationInfo represents the ASN.1 CHOICE type LocationInfo.
type LocationInfo struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode    `json:"-"`
	RoamingNumber  *ISDNAddressString `json:"RoamingNumber,omitempty"`
	MscNumber      *ISDNAddressString `json:"MscNumber,omitempty"`
}

// NewLocationInfoRoamingNumber creates a LocationInfo with the roamingNumber alternative.
func NewLocationInfoRoamingNumber(v ISDNAddressString) LocationInfo {
	return LocationInfo{
		Choice:        LocationInfoChoiceRoamingNumber,
		RoamingNumber: &v,
	}
}

// NewLocationInfoMscNumber creates a LocationInfo with the msc-Number alternative.
func NewLocationInfoMscNumber(v ISDNAddressString) LocationInfo {
	return LocationInfo{
		Choice:    LocationInfoChoiceMscNumber,
		MscNumber: &v,
	}
}

// HLRId represents the ASN.1 type HLR-Id (OCTET_STRING).
type HLRId = IMSI

// HLRList represents the ASN.1 type HLR-List (SEQUENCE_OF).
type HLRList struct {
	Values         []HLRId         `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// LMSI represents the ASN.1 type LMSI (OCTET_STRING).
type LMSI = []byte

// GlobalCellId represents the ASN.1 type GlobalCellId (OCTET_STRING).
type GlobalCellId = []byte

// NetworkResource represents the ASN.1 ENUMERATED type NetworkResource.
type NetworkResource int64

const (
	NetworkResourcePlmn           NetworkResource = 0
	NetworkResourceHlr            NetworkResource = 1
	NetworkResourceVlr            NetworkResource = 2
	NetworkResourcePvlr           NetworkResource = 3
	NetworkResourceControllingMSC NetworkResource = 4
	NetworkResourceVmsc           NetworkResource = 5
	NetworkResourceEir            NetworkResource = 6
	NetworkResourceRss            NetworkResource = 7
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v NetworkResource) String() string {
	switch v {
	case NetworkResourcePlmn:
		return "plmn"
	case NetworkResourceHlr:
		return "hlr"
	case NetworkResourceVlr:
		return "vlr"
	case NetworkResourcePvlr:
		return "pvlr"
	case NetworkResourceControllingMSC:
		return "controllingMSC"
	case NetworkResourceVmsc:
		return "vmsc"
	case NetworkResourceEir:
		return "eir"
	case NetworkResourceRss:
		return "rss"
	default:
		return "unknown"
	}
}

// Category represents the ASN.1 type Category (OCTET_STRING).
type Category = []byte

// BearerServiceList represents the ASN.1 type BearerServiceList (SEQUENCE_OF).
type BearerServiceList struct {
	Values         []BearerServiceCode `json:"Values"`
	berReplayNode_ *ber.ReplayNode     `json:"-"`
}

// TeleserviceList represents the ASN.1 type TeleserviceList (SEQUENCE_OF).
type TeleserviceList struct {
	Values         []TeleserviceCode `json:"Values"`
	berReplayNode_ *ber.ReplayNode   `json:"-"`
}

// BasicServiceCode choice constants.
const (
	BasicServiceCodeChoiceBearerService = 1
	BasicServiceCodeChoiceTeleservice   = 2
)

// BasicServiceCode represents the ASN.1 CHOICE type BasicServiceCode.
type BasicServiceCode struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode    `json:"-"`
	BearerService  *BearerServiceCode `json:"BearerService,omitempty"`
	Teleservice    *TeleserviceCode   `json:"Teleservice,omitempty"`
}

// NewBasicServiceCodeBearerService creates a BasicServiceCode with the bearerService alternative.
func NewBasicServiceCodeBearerService(v BearerServiceCode) BasicServiceCode {
	return BasicServiceCode{
		Choice:        BasicServiceCodeChoiceBearerService,
		BearerService: &v,
	}
}

// NewBasicServiceCodeTeleservice creates a BasicServiceCode with the teleservice alternative.
func NewBasicServiceCodeTeleservice(v TeleserviceCode) BasicServiceCode {
	return BasicServiceCode{
		Choice:      BasicServiceCodeChoiceTeleservice,
		Teleservice: &v,
	}
}

// BasicServiceList represents the ASN.1 type BasicServiceList (SEQUENCE_OF).
type BasicServiceList struct {
	Values         []BasicServiceCode `json:"Values"`
	berReplayNode_ *ber.ReplayNode    `json:"-"`
}

// BasicServiceGroupList represents the ASN.1 type BasicServiceGroupList (SEQUENCE_OF).
type BasicServiceGroupList struct {
	Values         []BasicServiceCode `json:"Values"`
	berReplayNode_ *ber.ReplayNode    `json:"-"`
}

// MarshalBERISDNAddressString encodes a typed standalone ISDNAddressString, preserving unchanged received BER.
func MarshalBERISDNAddressString(value *BERValue[ISDNAddressString], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required ISDNAddressString is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERISDNAddressString, marshalBERISDNAddressString, 2, UnmarshalBERISDNAddressString)

}
func marshalBERISDNAddressString(value *BERValue[ISDNAddressString], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value ISDNAddressString }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERISDNAddressString", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ISDN-AddressString", "SIZE (1..9)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERISDNAddressString", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ISDN-AddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ISDN-AddressString", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERISDNAddressString encodes a typed standalone ISDNAddressString using DER.
func MarshalDERISDNAddressString(value *BERValue[ISDNAddressString]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required ISDNAddressString is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value ISDNAddressString }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s24ff19_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ISDN-AddressString", "SIZE (1..9)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s24ff19_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ISDN-AddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ISDN-AddressString", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERISDNAddressString decodes one complete typed standalone ISDNAddressString from BER/DER.
func UnmarshalBERISDNAddressString(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[ISDNAddressString], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERISDNAddressString(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s24ff19_0, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value ISDNAddressString }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "ISDN-AddressString", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding ISDN-AddressString", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = ISDNAddressString(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 1 || len(v.Value) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ISDN-AddressString", "SIZE (1..9)", len(v.Value)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Value) < 1 || len(v.Value) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ISDN-AddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
				return constraintErr
			}
		}
		if offset != len(content) {
			return ber.ErrExtraData
		}
		return nil
	}
	if err := decode(); err != nil {
		return nil, err
	}
	decoded := &BERValue[ISDNAddressString]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERISDNAddressString); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes ExternalSignalInfo to BER format.
func (v *ExternalSignalInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ExternalSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ExternalSignalInfo).MarshalBER, (*ExternalSignalInfo).marshalBER, 3)

}
func (v *ExternalSignalInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := checkEncodedValue(opts, s24ff19_1, "20", "protocolId", "ENUMERATED {1, 2, 3, 4}", ber.ObserveInteger(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s24ff19_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_signalinfo, "signalInfo", "encoding", false)
	}
	children = append(children, enc_signalinfo...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s24ff19_1, children, i, &base_); err != nil {
			return nil, opaqueExtensionError(err, i)
		}
		_, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ExternalSignalInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ExternalSignalInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ExternalSignalInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ExternalSignalInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
		if constraintErr := checkEncodedValue(nil, s24ff19_1, "20", "protocolId", "ENUMERATED {1, 2, 3, 4}", ber.ObserveInteger(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s24ff19_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_signalinfo, "signalInfo", "encoding", true)
	}
	children = append(children, enc_signalinfo...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s24ff19_1, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ExternalSignalInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ExternalSignalInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ExternalSignalInfo from BER/DER format.
func (destination *ExternalSignalInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ExternalSignalInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(ExternalSignalInfo)

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
			var probe ExternalSignalInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s24ff19_1, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ExternalSignalInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ExternalSignalInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ExternalSignalInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ExternalSignalInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode protocolId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field protocolId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "protocolId", content[offset:])
		val_protocolid, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "protocolId", "decoding", false)
		}
		v.ProtocolId = ProtocolId(val_protocolid)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.ProtocolId) != 1 && int64(v.ProtocolId) != 2 && int64(v.ProtocolId) != 3 && int64(v.ProtocolId) != 4 {
			if constraintErr := checkDecodedValue(opts, s24ff19_1, "20", "protocolId", "ENUMERATED {1, 2, 3, 4}", ber.ObserveInteger(int64(v.ProtocolId))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode signalInfo
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field signalInfo", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "signalInfo", content[offset:])
		val_signalinfo, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "signalInfo", "decoding", false)
		}
		v.SignalInfo = SignalInfo(val_signalinfo)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo", Cause: extErr_}
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

// MarshalBERIMSI encodes a typed standalone IMSI, preserving unchanged received BER.
func MarshalBERIMSI(value *BERValue[IMSI], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required IMSI is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERIMSI, marshalBERIMSI, 2, UnmarshalBERIMSI)

}
func marshalBERIMSI(value *BERValue[IMSI], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value IMSI }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 3 || len(v.Value) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERIMSI", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "IMSI", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IMSI", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERIMSI encodes a typed standalone IMSI using DER.
func MarshalDERIMSI(value *BERValue[IMSI]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required IMSI is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value IMSI }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 3 || len(v.Value) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-CommonDataTypes.IMSI", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "IMSI", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IMSI", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERIMSI decodes one complete typed standalone IMSI from BER/DER.
func UnmarshalBERIMSI(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[IMSI], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERIMSI(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-CommonDataTypes.IMSI", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value IMSI }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "IMSI", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding IMSI", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = IMSI(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 3 || len(v.Value) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-CommonDataTypes.IMSI", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "IMSI", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
				return constraintErr
			}
		}
		if offset != len(content) {
			return ber.ErrExtraData
		}
		return nil
	}
	if err := decode(); err != nil {
		return nil, err
	}
	decoded := &BERValue[IMSI]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERIMSI); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SubscriberId to BER format.
func (v *SubscriberId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberId receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SubscriberId).MarshalBER, (*SubscriberId).marshalBER, 3)

}
func (v *SubscriberId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SubscriberId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SubscriberIdChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberId: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s24ff19_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "imsi", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SubscriberIdChoiceTmsi:
		if v.Tmsi == nil {
			return nil, fmt.Errorf("%w: choice SubscriberId: tmsi is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Tmsi))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "tmsi", "encoding", false)
		}
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s24ff19_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "tmsi", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SubscriberId", v.Choice)
	}
}

// MarshalDER encodes SubscriberId to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SubscriberId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SubscriberIdChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case SubscriberIdChoiceTmsi:
			return nil, qualifyBERError(err, "tmsi", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SubscriberId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SubscriberId) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SubscriberId from BER/DER format.
func (destination *SubscriberId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SubscriberId destination is nil", ber.ErrInvalidValue)
	}
	v := new(SubscriberId)
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
				opts, v, &v.berReplayNode_, (*SubscriberId).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SubscriberId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s24ff19_2, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SubscriberId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SubscriberId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SubscriberId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SubscriberId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SubscriberIdChoiceImsi
		ber.MarkPreflightTarget(opts, "imsi", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "imsi", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "imsi", "decoding", false)
		}
		tmp := IMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SubscriberIdChoiceTmsi
		ber.MarkPreflightTarget(opts, "tmsi", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "tmsi", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "tmsi", "decoding", false)
		}
		tmp := TMSI(decVal)
		v.Tmsi = &tmp
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for SubscriberId CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBERIMEI encodes a typed standalone IMEI, preserving unchanged received BER.
func MarshalBERIMEI(value *BERValue[IMEI], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required IMEI is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERIMEI, marshalBERIMEI, 2, UnmarshalBERIMEI)

}
func marshalBERIMEI(value *BERValue[IMEI], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value IMEI }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 8 || len(v.Value) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERIMEI", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "IMEI", "SIZE (8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IMEI", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERIMEI encodes a typed standalone IMEI using DER.
func MarshalDERIMEI(value *BERValue[IMEI]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required IMEI is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value IMEI }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 8 || len(v.Value) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-CommonDataTypes.IMEI", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "IMEI", "SIZE (8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IMEI", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERIMEI decodes one complete typed standalone IMEI from BER/DER.
func UnmarshalBERIMEI(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[IMEI], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERIMEI(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-CommonDataTypes.IMEI", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value IMEI }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "IMEI", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding IMEI", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = IMEI(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 8 || len(v.Value) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-CommonDataTypes.IMEI", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "IMEI", "SIZE (8)", len(v.Value)); constraintErr != nil {
				return constraintErr
			}
		}
		if offset != len(content) {
			return ber.ErrExtraData
		}
		return nil
	}
	if err := decode(); err != nil {
		return nil, err
	}
	decoded := &BERValue[IMEI]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERIMEI); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes LocationInfo to BER format.
func (v *LocationInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: LocationInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*LocationInfo).MarshalBER, (*LocationInfo).marshalBER, 3)

}
func (v *LocationInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *LocationInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case LocationInfoChoiceRoamingNumber:
		if v.RoamingNumber == nil {
			return nil, fmt.Errorf("%w: choice LocationInfo: roamingNumber is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.RoamingNumber))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "roamingNumber", "encoding", false)
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s24ff19_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..9)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s24ff19_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "roamingNumber", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case LocationInfoChoiceMscNumber:
		if v.MscNumber == nil {
			return nil, fmt.Errorf("%w: choice LocationInfo: msc-Number is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.MscNumber))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "msc-Number", "encoding", false)
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s24ff19_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s24ff19_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "msc-Number", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for LocationInfo", v.Choice)
	}
}

// MarshalDER encodes LocationInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LocationInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LocationInfo receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case LocationInfoChoiceRoamingNumber:
			return nil, qualifyBERError(err, "roamingNumber", "encoding", true)
		case LocationInfoChoiceMscNumber:
			return nil, qualifyBERError(err, "msc-Number", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding LocationInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *LocationInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LocationInfo from BER/DER format.
func (destination *LocationInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LocationInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(LocationInfo)
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
				opts, v, &v.berReplayNode_, (*LocationInfo).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe LocationInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s24ff19_3, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LocationInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for LocationInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for LocationInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding LocationInfo CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "LocationInfo", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = LocationInfoChoiceRoamingNumber
		ber.MarkPreflightTarget(opts, "roamingNumber", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "roamingNumber", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "roamingNumber", "decoding", false)
		}
		tmp := ISDNAddressString(decVal)
		v.RoamingNumber = &tmp
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..9)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = LocationInfoChoiceMscNumber
		ber.MarkPreflightTarget(opts, "msc-Number", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "msc-Number", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msc-Number", "decoding", false)
		}
		tmp := ISDNAddressString(decVal)
		v.MscNumber = &tmp
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for LocationInfo CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBERHLRId encodes a typed standalone HLRId, preserving unchanged received BER.
func MarshalBERHLRId(value *BERValue[HLRId], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required HLRId is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERHLRId, marshalBERHLRId, 2, UnmarshalBERHLRId)

}
func marshalBERHLRId(value *BERValue[HLRId], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value HLRId }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 3 || len(v.Value) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERHLRId", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "HLR-Id", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding HLR-Id", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERHLRId encodes a typed standalone HLRId using DER.
func MarshalDERHLRId(value *BERValue[HLRId]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required HLRId is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value HLRId }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 3 || len(v.Value) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, "MAP-CommonDataTypes.HLR-Id", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "HLR-Id", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding HLR-Id", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERHLRId decodes one complete typed standalone HLRId from BER/DER.
func UnmarshalBERHLRId(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[HLRId], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERHLRId(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-CommonDataTypes.HLR-Id", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value HLRId }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "HLR-Id", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding HLR-Id", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = HLRId(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 3 || len(v.Value) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, "MAP-CommonDataTypes.HLR-Id", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "HLR-Id", "SIZE (3..8)", len(v.Value)); constraintErr != nil {
				return constraintErr
			}
		}
		if offset != len(content) {
			return ber.ErrExtraData
		}
		return nil
	}
	if err := decode(); err != nil {
		return nil, err
	}
	decoded := &BERValue[HLRId]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERHLRId); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERHLRList encodes a HLRList list to BER.
func MarshalBERHLRList(collection *HLRList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERHLRList, marshalBERHLRList, 3, UnmarshalBERHLRList)

}
func marshalBERHLRList(collection *HLRList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERHLRList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "HLR-List", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 3 || len(elem) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERHLRList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", elemIndex), "SIZE (3..8)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearHLRList(encoder *ber.LinearEncoder, collection *HLRList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERHLRList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERHLRList encodes a HLRList list to DER.
func MarshalDERHLRList(collection *HLRList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, s24ff19_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "HLR-List", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 3 || len(elem) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s24ff19_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", elemIndex), "SIZE (3..8)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding HLRList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearHLRList(encoder *ber.LinearEncoder, collection *HLRList) ([]byte, error) {
	encoded, err := MarshalDERHLRList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERHLRList decodes a HLRList list from BER.
func UnmarshalBERHLRList(data []byte, opts ...ber.DecodeOption) (returnValue *HLRList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERHLRList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s24ff19_4, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding HLRList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "HLRList", Cause: ber.ErrExtraData}
	}
	var result []HLRId
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 3 || len(val) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", len(result)), "SIZE (3..8)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, HLRId(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, s24ff19_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "HLR-List", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &HLRList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERHLRList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERBearerServiceList encodes a BearerServiceList list to BER.
func MarshalBERBearerServiceList(collection *BearerServiceList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERBearerServiceList, marshalBERBearerServiceList, 3, UnmarshalBERBearerServiceList)

}
func marshalBERBearerServiceList(collection *BearerServiceList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERBearerServiceList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "BearerServiceList", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERBearerServiceList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearBearerServiceList(encoder *ber.LinearEncoder, collection *BearerServiceList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERBearerServiceList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERBearerServiceList encodes a BearerServiceList list to DER.
func MarshalDERBearerServiceList(collection *BearerServiceList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, s24ff19_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "BearerServiceList", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s24ff19_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding BearerServiceList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearBearerServiceList(encoder *ber.LinearEncoder, collection *BearerServiceList) ([]byte, error) {
	encoded, err := MarshalDERBearerServiceList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERBearerServiceList decodes a BearerServiceList list from BER.
func UnmarshalBERBearerServiceList(data []byte, opts ...ber.DecodeOption) (returnValue *BearerServiceList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERBearerServiceList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s24ff19_5, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding BearerServiceList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BearerServiceList", Cause: ber.ErrExtraData}
	}
	var result []BearerServiceCode
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 1 || len(val) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", len(result)), "SIZE (1)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, BearerServiceCode(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, s24ff19_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "BearerServiceList", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &BearerServiceList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERBearerServiceList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERTeleserviceList encodes a TeleserviceList list to BER.
func MarshalBERTeleserviceList(collection *TeleserviceList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERTeleserviceList, marshalBERTeleserviceList, 3, UnmarshalBERTeleserviceList)

}
func marshalBERTeleserviceList(collection *TeleserviceList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 20 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERTeleserviceList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "TeleserviceList", "SIZE (1..20)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERTeleserviceList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, encodedElem...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearTeleserviceList(encoder *ber.LinearEncoder, collection *TeleserviceList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERTeleserviceList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERTeleserviceList encodes a TeleserviceList list to DER.
func MarshalDERTeleserviceList(collection *TeleserviceList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 20 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, s24ff19_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "TeleserviceList", "SIZE (1..20)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s24ff19_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, qualifyBERError(encodeErr_encodedElem, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TeleserviceList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearTeleserviceList(encoder *ber.LinearEncoder, collection *TeleserviceList) ([]byte, error) {
	encoded, err := MarshalDERTeleserviceList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERTeleserviceList decodes a TeleserviceList list from BER.
func UnmarshalBERTeleserviceList(data []byte, opts ...ber.DecodeOption) (returnValue *TeleserviceList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERTeleserviceList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s24ff19_6, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding TeleserviceList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "TeleserviceList", Cause: ber.ErrExtraData}
	}
	var result []TeleserviceCode
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, osErr := ber.DecodeOctetString(elementData, opts...)
		if osErr != nil {
			return nil, qualifyBERError(osErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if len(val) < 1 || len(val) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", len(result)), "SIZE (1)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, TeleserviceCode(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 20 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, s24ff19_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "TeleserviceList", "SIZE (1..20)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &TeleserviceList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERTeleserviceList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes BasicServiceCode to BER format.
func (v *BasicServiceCode) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: BasicServiceCode receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*BasicServiceCode).MarshalBER, (*BasicServiceCode).marshalBER, 3)

}
func (v *BasicServiceCode) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *BasicServiceCode) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case BasicServiceCodeChoiceBearerService:
		if v.BearerService == nil {
			return nil, fmt.Errorf("%w: choice BasicServiceCode: bearerService is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.BearerService))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "bearerService", "encoding", false)
		}
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s24ff19_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "bearerService", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case BasicServiceCodeChoiceTeleservice:
		if v.Teleservice == nil {
			return nil, fmt.Errorf("%w: choice BasicServiceCode: teleservice is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Teleservice))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "teleservice", "encoding", false)
		}
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s24ff19_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "teleservice", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for BasicServiceCode", v.Choice)
	}
}

// MarshalDER encodes BasicServiceCode to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *BasicServiceCode) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BasicServiceCode receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case BasicServiceCodeChoiceBearerService:
			return nil, qualifyBERError(err, "bearerService", "encoding", true)
		case BasicServiceCodeChoiceTeleservice:
			return nil, qualifyBERError(err, "teleservice", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding BasicServiceCode as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *BasicServiceCode) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes BasicServiceCode from BER/DER format.
func (destination *BasicServiceCode) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: BasicServiceCode destination is nil", ber.ErrInvalidValue)
	}
	v := new(BasicServiceCode)
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
				opts, v, &v.berReplayNode_, (*BasicServiceCode).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe BasicServiceCode
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s24ff19_7, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = BasicServiceCode{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for BasicServiceCode CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for BasicServiceCode: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding BasicServiceCode CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "BasicServiceCode", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = BasicServiceCodeChoiceBearerService
		ber.MarkPreflightTarget(opts, "bearerService", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "bearerService", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "bearerService", "decoding", false)
		}
		tmp := BearerServiceCode(decVal)
		v.BearerService = &tmp
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = BasicServiceCodeChoiceTeleservice
		ber.MarkPreflightTarget(opts, "teleservice", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "teleservice", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "teleservice", "decoding", false)
		}
		tmp := TeleserviceCode(decVal)
		v.Teleservice = &tmp
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s24ff19_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for BasicServiceCode CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBERBasicServiceList encodes a BasicServiceList list to BER.
func MarshalBERBasicServiceList(collection *BasicServiceList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERBasicServiceList, marshalBERBasicServiceList, 3, UnmarshalBERBasicServiceList)

}
func marshalBERBasicServiceList(collection *BasicServiceList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 70 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERBasicServiceList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "BasicServiceList", "SIZE (1..70)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
		ber.RecordGeneratedBERChildPlacement(opts, len(children)-len(enc), enc)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearBasicServiceList(encoder *ber.LinearEncoder, collection *BasicServiceList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERBasicServiceList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERBasicServiceList encodes a BasicServiceList list to DER.
func MarshalDERBasicServiceList(collection *BasicServiceList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 70 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, "MAP-CommonDataTypes.BasicServiceList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "BasicServiceList", "SIZE (1..70)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding BasicServiceList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearBasicServiceList(encoder *ber.LinearEncoder, collection *BasicServiceList) ([]byte, error) {
	encoded, err := MarshalDERBasicServiceList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERBasicServiceList decodes a BasicServiceList list from BER.
func UnmarshalBERBasicServiceList(data []byte, opts ...ber.DecodeOption) (returnValue *BasicServiceList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERBasicServiceList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-CommonDataTypes.BasicServiceList", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding BasicServiceList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BasicServiceList", Cause: ber.ErrExtraData}
	}
	var result []BasicServiceCode
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem BasicServiceCode
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeIndexOptions(opts, len(result))...); unmErr != nil {
			return nil, qualifyBERError(unmErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 70 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, "MAP-CommonDataTypes.BasicServiceList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "BasicServiceList", "SIZE (1..70)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &BasicServiceList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERBasicServiceList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERBasicServiceGroupList encodes a BasicServiceGroupList list to BER.
func MarshalBERBasicServiceGroupList(collection *BasicServiceGroupList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERBasicServiceGroupList, marshalBERBasicServiceGroupList, 3, UnmarshalBERBasicServiceGroupList)

}
func marshalBERBasicServiceGroupList(collection *BasicServiceGroupList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-CommonDataTypes.marshalBERBasicServiceGroupList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "BasicServiceGroupList", "SIZE (1..13)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalBER(ber.ChildEncodeOptions(opts, fmt.Sprintf("element[%d]", elemIndex))...)
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", false)
		}
		children = append(children, enc...)
		ber.RecordGeneratedBERChildPlacement(opts, len(children)-len(enc), enc)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearBasicServiceGroupList(encoder *ber.LinearEncoder, collection *BasicServiceGroupList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERBasicServiceGroupList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERBasicServiceGroupList encodes a BasicServiceGroupList list to DER.
func MarshalDERBasicServiceGroupList(collection *BasicServiceGroupList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, "MAP-CommonDataTypes.BasicServiceGroupList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "BasicServiceGroupList", "SIZE (1..13)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex := range list {
		_ = elemIndex
		elem := &list[elemIndex]
		enc, err := elem.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, fmt.Sprintf("element[%d]",
				elemIndex),

				"encoding", true)
		}
		children = append(children, enc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding BasicServiceGroupList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearBasicServiceGroupList(encoder *ber.LinearEncoder, collection *BasicServiceGroupList) ([]byte, error) {
	encoded, err := MarshalDERBasicServiceGroupList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERBasicServiceGroupList decodes a BasicServiceGroupList list from BER.
func UnmarshalBERBasicServiceGroupList(data []byte, opts ...ber.DecodeOption) (returnValue *BasicServiceGroupList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERBasicServiceGroupList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-CommonDataTypes.BasicServiceGroupList", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding BasicServiceGroupList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BasicServiceGroupList", Cause: ber.ErrExtraData}
	}
	var result []BasicServiceCode
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem BasicServiceCode
		_, n, _, tlvErr := ber.DecodeTLV(elementData, opts...)
		if tlvErr != nil {
			return nil, qualifyBERError(tlvErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if unmErr := elem.UnmarshalBER(elementData[:n], ber.ChildDecodeIndexOptions(opts, len(result))...); unmErr != nil {
			return nil, qualifyBERError(unmErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		result = append(result, elem)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 13 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, "MAP-CommonDataTypes.BasicServiceGroupList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "BasicServiceGroupList", "SIZE (1..13)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &BasicServiceGroupList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERBasicServiceGroupList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

const (
	s24ff19_0 = "MAP-CommonDataTypes.ISDN-AddressString"
	s24ff19_1 = "MAP-CommonDataTypes.ExternalSignalInfo"
	s24ff19_2 = "MAP-CommonDataTypes.SubscriberId"
	s24ff19_3 = "MAP-CommonDataTypes.LocationInfo"
	s24ff19_4 = "MAP-CommonDataTypes.HLR-List"
	s24ff19_5 = "MAP-CommonDataTypes.BearerServiceList"
	s24ff19_6 = "MAP-CommonDataTypes.TeleserviceList"
	s24ff19_7 = "MAP-CommonDataTypes.BasicServiceCode"
)
