// Code generated from ASN.1 module "MAP-SM-DataTypes". DO NOT EDIT.

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

// RoutingInfoForSMArg represents the ASN.1 type RoutingInfoForSM-Arg (SEQUENCE).
type RoutingInfoForSMArg struct {
	Msisdn               ISDNAddressString `asn1:"tag:0,context,implicit"`
	SmRPPRI              bool              `asn1:"tag:1,context,implicit"`
	berSmRPPRIRaw_       byte              `asn1:"-" json:"-"`
	ServiceCentreAddress AddressString     `asn1:"tag:2,context,implicit"`
	Teleservice          *TeleserviceCode  `asn1:"tag:5,context,implicit,optional" json:"Teleservice,omitempty"`
	ExtCount_            int64             `asn1:"-" json:"-"`
	ExtPresent_          []bool            `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// RoutingInfoForSMRes represents the ASN.1 type RoutingInfoForSM-Res (SEQUENCE).
type RoutingInfoForSMRes struct {
	Imsi                 IMSI                 `asn1:""`
	LocationInfoWithLMSI LocationInfoWithLMSI `asn1:"tag:0,context,implicit"`
	MwdSet               *bool                `asn1:"tag:2,context,implicit,optional" json:"MwdSet,omitempty"`
	berMwdSetRaw_        byte                 `asn1:"-" json:"-"`
	ExtCount_            int64                `asn1:"-" json:"-"`
	ExtPresent_          []bool               `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// LocationInfoWithLMSI represents the ASN.1 type LocationInfoWithLMSI (SEQUENCE).
type LocationInfoWithLMSI struct {
	LocationInfo LocationInfo `asn1:""`
	Lmsi         *LMSI        `asn1:",optional" json:"Lmsi,omitempty"`
	ExtCount_    int64        `asn1:"-" json:"-"`
	ExtPresent_  []bool       `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ForwardSMArg represents the ASN.1 type ForwardSM-Arg (SEQUENCE).
type ForwardSMArg struct {
	SmRPDA             SMRPDA     `asn1:""`
	SmRPOA             SMRPOA     `asn1:""`
	SmRPUI             SignalInfo `asn1:""`
	MoreMessagesToSend *struct{}  `asn1:",optional" json:"MoreMessagesToSend,omitempty"`
	ExtCount_          int64      `asn1:"-" json:"-"`
	ExtPresent_        []bool     `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SMRPDA choice constants.
const (
	SMRPDAChoiceImsi                   = 1
	SMRPDAChoiceLmsi                   = 2
	SMRPDAChoiceRoamingNumber          = 3
	SMRPDAChoiceServiceCentreAddressDA = 4
	SMRPDAChoiceNoSMRPDA               = 5
)

// SMRPDA represents the ASN.1 CHOICE type SM-RP-DA.
type SMRPDA struct {
	Choice                 int
	berReplayNode_         *ber.ReplayNode    `json:"-"`
	Imsi                   *IMSI              `json:"Imsi,omitempty"`
	Lmsi                   *LMSI              `json:"Lmsi,omitempty"`
	RoamingNumber          *ISDNAddressString `json:"RoamingNumber,omitempty"`
	ServiceCentreAddressDA *AddressString     `json:"ServiceCentreAddressDA,omitempty"`
	NoSMRPDA               *struct{}          `json:"NoSMRPDA,omitempty"`
}

// NewSMRPDAImsi creates a SMRPDA with the imsi alternative.
func NewSMRPDAImsi(v IMSI) SMRPDA {
	return SMRPDA{
		Choice: SMRPDAChoiceImsi,
		Imsi:   &v,
	}
}

// NewSMRPDALmsi creates a SMRPDA with the lmsi alternative.
func NewSMRPDALmsi(v LMSI) SMRPDA {
	return SMRPDA{
		Choice: SMRPDAChoiceLmsi,
		Lmsi:   &v,
	}
}

// NewSMRPDARoamingNumber creates a SMRPDA with the roamingNumber alternative.
func NewSMRPDARoamingNumber(v ISDNAddressString) SMRPDA {
	return SMRPDA{
		Choice:        SMRPDAChoiceRoamingNumber,
		RoamingNumber: &v,
	}
}

// NewSMRPDAServiceCentreAddressDA creates a SMRPDA with the serviceCentreAddressDA alternative.
func NewSMRPDAServiceCentreAddressDA(v AddressString) SMRPDA {
	return SMRPDA{
		Choice:                 SMRPDAChoiceServiceCentreAddressDA,
		ServiceCentreAddressDA: &v,
	}
}

// NewSMRPDANoSMRPDA creates a SMRPDA with the noSM-RP-DA alternative.
func NewSMRPDANoSMRPDA(v struct{}) SMRPDA {
	return SMRPDA{
		Choice:   SMRPDAChoiceNoSMRPDA,
		NoSMRPDA: &v,
	}
}

// SMRPOA choice constants.
const (
	SMRPOAChoiceMsisdn                 = 1
	SMRPOAChoiceServiceCentreAddressOA = 2
	SMRPOAChoiceNoSMRPOA               = 3
)

// SMRPOA represents the ASN.1 CHOICE type SM-RP-OA.
type SMRPOA struct {
	Choice                 int
	berReplayNode_         *ber.ReplayNode    `json:"-"`
	Msisdn                 *ISDNAddressString `json:"Msisdn,omitempty"`
	ServiceCentreAddressOA *AddressString     `json:"ServiceCentreAddressOA,omitempty"`
	NoSMRPOA               *struct{}          `json:"NoSMRPOA,omitempty"`
}

// NewSMRPOAMsisdn creates a SMRPOA with the msisdn alternative.
func NewSMRPOAMsisdn(v ISDNAddressString) SMRPOA {
	return SMRPOA{
		Choice: SMRPOAChoiceMsisdn,
		Msisdn: &v,
	}
}

// NewSMRPOAServiceCentreAddressOA creates a SMRPOA with the serviceCentreAddressOA alternative.
func NewSMRPOAServiceCentreAddressOA(v AddressString) SMRPOA {
	return SMRPOA{
		Choice:                 SMRPOAChoiceServiceCentreAddressOA,
		ServiceCentreAddressOA: &v,
	}
}

// NewSMRPOANoSMRPOA creates a SMRPOA with the noSM-RP-OA alternative.
func NewSMRPOANoSMRPOA(v struct{}) SMRPOA {
	return SMRPOA{
		Choice:   SMRPOAChoiceNoSMRPOA,
		NoSMRPOA: &v,
	}
}

// ReportSMDeliveryStatusArg represents the ASN.1 type ReportSM-DeliveryStatusArg (SEQUENCE).
type ReportSMDeliveryStatusArg struct {
	Msisdn               ISDNAddressString  `asn1:""`
	ServiceCentreAddress AddressString      `asn1:""`
	SmDeliveryOutcome    *SMDeliveryOutcome `asn1:",optional" json:"SmDeliveryOutcome,omitempty"`
	ExtCount_            int64              `asn1:"-" json:"-"`
	ExtPresent_          []bool             `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SMDeliveryOutcome represents the ASN.1 ENUMERATED type SM-DeliveryOutcome.
type SMDeliveryOutcome int64

const (
	SMDeliveryOutcomeMemoryCapacityExceeded SMDeliveryOutcome = 0
	SMDeliveryOutcomeAbsentSubscriber       SMDeliveryOutcome = 1
	SMDeliveryOutcomeSuccessfulTransfer     SMDeliveryOutcome = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v SMDeliveryOutcome) String() string {
	switch v {
	case SMDeliveryOutcomeMemoryCapacityExceeded:
		return "memoryCapacityExceeded"
	case SMDeliveryOutcomeAbsentSubscriber:
		return "absentSubscriber"
	case SMDeliveryOutcomeSuccessfulTransfer:
		return "successfulTransfer"
	default:
		return "unknown"
	}
}

// AlertServiceCentreArg represents the ASN.1 type AlertServiceCentreArg (SEQUENCE).
type AlertServiceCentreArg struct {
	Msisdn               ISDNAddressString `asn1:""`
	ServiceCentreAddress AddressString     `asn1:""`
	ExtCount_            int64             `asn1:"-" json:"-"`
	ExtPresent_          []bool            `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// InformServiceCentreArg represents the ASN.1 type InformServiceCentreArg (SEQUENCE).
type InformServiceCentreArg struct {
	StoredMSISDN *ISDNAddressString `asn1:",optional" json:"StoredMSISDN,omitempty"`
	MwStatus     *MWStatus          `asn1:",optional" json:"MwStatus,omitempty"`
	ExtCount_    int64              `asn1:"-" json:"-"`
	ExtPresent_  []bool             `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MWStatus represents the ASN.1 type MW-Status (BIT_STRING).
type MWStatus = runtime.BitString

const (
	// MWStatusScAddressNotIncluded is position 0 of ASN.1 named bit sc-AddressNotIncluded of MW-Status (CCITT X.208 (11/1988) §17).
	MWStatusScAddressNotIncluded = 0
	// MWStatusMnrfSet is position 1 of ASN.1 named bit mnrf-Set of MW-Status (CCITT X.208 (11/1988) §17).
	MWStatusMnrfSet = 1
	// MWStatusMcefSet is position 2 of ASN.1 named bit mcef-Set of MW-Status (CCITT X.208 (11/1988) §17).
	MWStatusMcefSet = 2
)

// ReadyForSMArg represents the ASN.1 type ReadyForSM-Arg (SEQUENCE).
type ReadyForSMArg struct {
	Imsi        IMSI        `asn1:"tag:0,context,implicit"`
	AlertReason AlertReason `asn1:""`
	ExtCount_   int64       `asn1:"-" json:"-"`
	ExtPresent_ []bool      `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// AlertReason represents the ASN.1 ENUMERATED type AlertReason.
type AlertReason int64

const (
	AlertReasonMsPresent       AlertReason = 0
	AlertReasonMemoryAvailable AlertReason = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v AlertReason) String() string {
	switch v {
	case AlertReasonMsPresent:
		return "ms-Present"
	case AlertReasonMemoryAvailable:
		return "memoryAvailable"
	default:
		return "unknown"
	}
}

// MarshalBER encodes RoutingInfoForSMArg to BER format.
func (v *RoutingInfoForSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RoutingInfoForSMArg).MarshalBER, (*RoutingInfoForSMArg).marshalBER, 3)

}
func (v *RoutingInfoForSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	var enc_smrppri []byte
	if ber.BERReplayEnabled(opts) && v.berSmRPPRIRaw_ != 0 && v.SmRPPRI {
		enc_smrppri = ber.EncodeBooleanRaw(v.berSmRPPRIRaw_)
	} else {
		enc_smrppri = ber.EncodeBoolean(v.SmRPPRI)
	}
	retagged_enc_smrppri, tagErr_enc_smrppri := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smrppri)
	if tagErr_enc_smrppri != nil {
		return nil, qualifyBERError(tagErr_enc_smrppri, "sm-RP-PRI", "encoding", false)
	}
	enc_smrppri = retagged_enc_smrppri
	children = append(children, enc_smrppri...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", false)
	}
	retagged_enc_servicecentreaddress, tagErr_enc_servicecentreaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicecentreaddress)
	if tagErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(tagErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", false)
	}
	enc_servicecentreaddress = retagged_enc_servicecentreaddress
	children = append(children, enc_servicecentreaddress...)
	if v.Teleservice != nil {
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(*v.Teleservice))
		if encodeErr_enc_teleservice != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservice, "teleservice", "encoding", false)
		}
		retagged_enc_teleservice, tagErr_enc_teleservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_teleservice)
		if tagErr_enc_teleservice != nil {
			return nil, qualifyBERError(tagErr_enc_teleservice, "teleservice", "encoding", false)
		}
		enc_teleservice = retagged_enc_teleservice
		children = append(children, enc_teleservice...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s913b50_0, children, i, &base_); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s913b50_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *RoutingInfoForSMArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes RoutingInfoForSMArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RoutingInfoForSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	enc_smrppri := ber.EncodeBoolean(v.SmRPPRI)
	retagged_enc_smrppri, tagErr_enc_smrppri := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_smrppri)
	if tagErr_enc_smrppri != nil {
		return nil, qualifyBERError(tagErr_enc_smrppri, "sm-RP-PRI", "encoding", true)
	}
	enc_smrppri = retagged_enc_smrppri
	children = append(children, enc_smrppri...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", true)
	}
	retagged_enc_servicecentreaddress, tagErr_enc_servicecentreaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_servicecentreaddress)
	if tagErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(tagErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", true)
	}
	enc_servicecentreaddress = retagged_enc_servicecentreaddress
	children = append(children, enc_servicecentreaddress...)
	if v.Teleservice != nil {
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(*v.Teleservice))
		if encodeErr_enc_teleservice != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservice, "teleservice", "encoding", true)
		}
		retagged_enc_teleservice, tagErr_enc_teleservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_teleservice)
		if tagErr_enc_teleservice != nil {
			return nil, qualifyBERError(tagErr_enc_teleservice, "teleservice", "encoding", true)
		}
		enc_teleservice = retagged_enc_teleservice
		children = append(children, enc_teleservice...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s913b50_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s913b50_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding RoutingInfoForSMArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *RoutingInfoForSMArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RoutingInfoForSMArg from BER/DER format.
func (destination *RoutingInfoForSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RoutingInfoForSMArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(RoutingInfoForSMArg)

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
			var probe RoutingInfoForSMArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s913b50_0, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RoutingInfoForSMArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RoutingInfoForSMArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding RoutingInfoForSMArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfoForSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field msisdn", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("%w: expected tag [%s %d] for msisdn, got %s", ber.ErrUnexpectedElement, "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
		decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msisdn", "decoding", false)
		}
		if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_msisdn), "msisdn", "decoding", false)
		}
		decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msisdn", "decoding", false)
		}
		v.Msisdn = ISDNAddressString(decVal_msisdn)
		if offset > len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_msisdn
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode sm-RP-PRI
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field sm-RP-PRI", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("%w: expected tag [%s %d] for sm-RP-PRI, got %s", ber.ErrUnexpectedElement, "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-PRI", content[offset:])
		decodedTag_smrppri, n_smrppri, rawVal_smrppri, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "sm-RP-PRI", "decoding", false)
		}
		if decodedTag_smrppri.Class != tag.ClassContextSpecific || decodedTag_smrppri.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_smrppri), "sm-RP-PRI", "decoding", false)
		}
		if decodedTag_smrppri.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_smrppri), "sm-RP-PRI", "decoding", false)
		}
		decVal_smrppri, boolErr := ber.DecodeBooleanValue(rawVal_smrppri)
		if boolErr != nil {
			return qualifyBERError(boolErr, "sm-RP-PRI", "decoding", false)
		}
		if len(rawVal_smrppri) == 1 && rawVal_smrppri[0] != 0 && rawVal_smrppri[0] != 0xff {
			ber.MarkBERNonCanonical(opts)
		}
		if len(rawVal_smrppri) == 1 {
			v.berSmRPPRIRaw_ = rawVal_smrppri[0]
		}
		v.SmRPPRI = decVal_smrppri
		if offset < 0 || offset >
			len(content) || n_smrppri < 0 || n_smrppri > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_smrppri
	}
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field serviceCentreAddress", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("%w: expected tag [%s %d] for serviceCentreAddress, got %s", ber.ErrUnexpectedElement, "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "serviceCentreAddress", content[offset:])
		decodedTag_servicecentreaddress, n_servicecentreaddress, rawVal_servicecentreaddress, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "serviceCentreAddress", "decoding", false)
		}
		if decodedTag_servicecentreaddress.Class != tag.ClassContextSpecific || decodedTag_servicecentreaddress.Number != 2 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_servicecentreaddress), "serviceCentreAddress", "decoding", false)
		}
		decVal_servicecentreaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_servicecentreaddress.Constructed, rawVal_servicecentreaddress, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "serviceCentreAddress", "decoding", false)
		}
		v.ServiceCentreAddress = AddressString(decVal_servicecentreaddress)
		if offset < 0 || offset >
			len(content) || n_servicecentreaddress < 0 || n_servicecentreaddress >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_servicecentreaddress
		if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode teleservice
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "teleservice", content[offset:])
				decodedTag_teleservice, n_teleservice, rawVal_teleservice, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "teleservice", "decoding", false)
				}
				if decodedTag_teleservice.Class != tag.ClassContextSpecific || decodedTag_teleservice.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_teleservice), "teleservice", "decoding", false)
				}
				decVal_teleservice, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_teleservice.Constructed, rawVal_teleservice, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "teleservice", "decoding", false)
				}
				tmp_teleservice := TeleserviceCode(decVal_teleservice)
				v.Teleservice = &tmp_teleservice
				if offset < 0 || offset >
					len(content) || n_teleservice < 0 || n_teleservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_teleservice
				if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s913b50_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes RoutingInfoForSMRes to BER format.
func (v *RoutingInfoForSMRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RoutingInfoForSMRes).MarshalBER, (*RoutingInfoForSMRes).marshalBER, 3)

}
func (v *RoutingInfoForSMRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	enc_locationinfowithlmsi, err := v.LocationInfoWithLMSI.MarshalBER(ber.ChildEncodeOptions(opts, "locationInfoWithLMSI")...)
	if err != nil {
		return nil, qualifyBERError(err, "locationInfoWithLMSI", "encoding", false)
	}
	retagged_enc_locationinfowithlmsi, tagErr_enc_locationinfowithlmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationinfowithlmsi)
	if tagErr_enc_locationinfowithlmsi != nil {
		return nil, qualifyBERError(tagErr_enc_locationinfowithlmsi, "locationInfoWithLMSI", "encoding", false)
	}
	enc_locationinfowithlmsi = retagged_enc_locationinfowithlmsi
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_locationinfowithlmsi)
	children = append(children, enc_locationinfowithlmsi...)
	if v.MwdSet != nil {
		var enc_mwdset []byte
		if ber.BERReplayEnabled(opts) && v.berMwdSetRaw_ != 0 && *v.MwdSet {
			enc_mwdset = ber.EncodeBooleanRaw(v.berMwdSetRaw_)
		} else {
			enc_mwdset = ber.EncodeBoolean(*v.MwdSet)
		}
		retagged_enc_mwdset, tagErr_enc_mwdset := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_mwdset)
		if tagErr_enc_mwdset != nil {
			return nil, qualifyBERError(tagErr_enc_mwdset, "mwd-Set", "encoding", false)
		}
		enc_mwdset = retagged_enc_mwdset
		children = append(children, enc_mwdset...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s913b50_1, children, i, &base_); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s913b50_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *RoutingInfoForSMRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes RoutingInfoForSMRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RoutingInfoForSMRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfoForSMRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	enc_locationinfowithlmsi, err := v.LocationInfoWithLMSI.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "locationInfoWithLMSI", "encoding", true)
	}
	retagged_enc_locationinfowithlmsi, tagErr_enc_locationinfowithlmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_locationinfowithlmsi)
	if tagErr_enc_locationinfowithlmsi != nil {
		return nil, qualifyBERError(tagErr_enc_locationinfowithlmsi, "locationInfoWithLMSI", "encoding", true)
	}
	enc_locationinfowithlmsi = retagged_enc_locationinfowithlmsi
	children = append(children, enc_locationinfowithlmsi...)
	if v.MwdSet != nil {
		enc_mwdset := ber.EncodeBoolean(*v.MwdSet)
		retagged_enc_mwdset, tagErr_enc_mwdset := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_mwdset)
		if tagErr_enc_mwdset != nil {
			return nil, qualifyBERError(tagErr_enc_mwdset, "mwd-Set", "encoding", true)
		}
		enc_mwdset = retagged_enc_mwdset
		children = append(children, enc_mwdset...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s913b50_1, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s913b50_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding RoutingInfoForSMRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *RoutingInfoForSMRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RoutingInfoForSMRes from BER/DER format.
func (destination *RoutingInfoForSMRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RoutingInfoForSMRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(RoutingInfoForSMRes)

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
			var probe RoutingInfoForSMRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s913b50_1, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RoutingInfoForSMRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RoutingInfoForSMRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding RoutingInfoForSMRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfoForSMRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field imsi", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "imsi", content[offset:])
		val_imsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "imsi", "decoding", false)
		}
		v.Imsi = IMSI(val_imsi)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode locationInfoWithLMSI
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field locationInfoWithLMSI", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("%w: expected tag [%s %d] for locationInfoWithLMSI, got %s", ber.ErrUnexpectedElement, "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "locationInfoWithLMSI", content[offset:])
		decodedTag_locationinfowithlmsi, n_locationinfowithlmsi, rawVal_locationinfowithlmsi, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "locationInfoWithLMSI", "decoding", false)
		}
		if decodedTag_locationinfowithlmsi.Class != tag.ClassContextSpecific || decodedTag_locationinfowithlmsi.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_locationinfowithlmsi), "locationInfoWithLMSI", "decoding", false)
		}
		if decodedTag_locationinfowithlmsi.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_locationinfowithlmsi), "locationInfoWithLMSI", "decoding", false)
		}
		_ = rawVal_locationinfowithlmsi
		if offset < 0 || offset >
			len(content) || n_locationinfowithlmsi < 0 || n_locationinfowithlmsi >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		reconstructed_locationinfowithlmsi, reconstructionErr_locationinfowithlmsi := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_locationinfowithlmsi])
		if reconstructionErr_locationinfowithlmsi != nil {
			return qualifyBERError(reconstructionErr_locationinfowithlmsi, "locationInfoWithLMSI", "decoding", false)
		}
		if unmErr := v.LocationInfoWithLMSI.UnmarshalBER(reconstructed_locationinfowithlmsi, ber.ChildDecodeOptions(opts, "locationInfoWithLMSI")...); unmErr != nil {
			return qualifyBERError(unmErr, "locationInfoWithLMSI", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_locationinfowithlmsi < 0 || n_locationinfowithlmsi >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_locationinfowithlmsi
	}
	// Decode mwd-Set
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "mwd-Set", content[offset:])
				decodedTag_mwdset, n_mwdset, rawVal_mwdset, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mwd-Set", "decoding", false)
				}
				if decodedTag_mwdset.Class != tag.ClassContextSpecific || decodedTag_mwdset.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_mwdset), "mwd-Set", "decoding", false)
				}
				if decodedTag_mwdset.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_mwdset), "mwd-Set", "decoding", false)
				}
				decVal_mwdset, boolErr := ber.DecodeBooleanValue(rawVal_mwdset)
				if boolErr != nil {
					return qualifyBERError(boolErr, "mwd-Set", "decoding", false)
				}
				if len(rawVal_mwdset) == 1 && rawVal_mwdset[0] != 0 && rawVal_mwdset[0] != 0xff {
					ber.MarkBERNonCanonical(opts)
				}
				if len(rawVal_mwdset) == 1 {
					v.berMwdSetRaw_ = rawVal_mwdset[0]
				}
				v.MwdSet = &decVal_mwdset
				if offset < 0 || offset >
					len(content) || n_mwdset < 0 || n_mwdset > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mwdset
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "RoutingInfoForSMRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s913b50_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes LocationInfoWithLMSI to BER format.
func (v *LocationInfoWithLMSI) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: LocationInfoWithLMSI receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*LocationInfoWithLMSI).MarshalBER, (*LocationInfoWithLMSI).marshalBER, 3)

}
func (v *LocationInfoWithLMSI) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_locationinfo, err := v.LocationInfo.MarshalBER(ber.ChildEncodeOptions(opts, "locationInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "locationInfo", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_locationinfo)
	children = append(children, enc_locationinfo...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", false)
		}
		children = append(children, enc_lmsi...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s913b50_2, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s913b50_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *LocationInfoWithLMSI) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes LocationInfoWithLMSI to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *LocationInfoWithLMSI) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: LocationInfoWithLMSI receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_locationinfo, err := v.LocationInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "locationInfo", "encoding", true)
	}
	children = append(children, enc_locationinfo...)
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", true)
		}
		children = append(children, enc_lmsi...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s913b50_2, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s913b50_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding LocationInfoWithLMSI as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *LocationInfoWithLMSI) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes LocationInfoWithLMSI from BER/DER format.
func (destination *LocationInfoWithLMSI) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: LocationInfoWithLMSI destination is nil", ber.ErrInvalidValue)
	}
	v := new(LocationInfoWithLMSI)

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
			var probe LocationInfoWithLMSI
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s913b50_2, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = LocationInfoWithLMSI{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*LocationInfoWithLMSI).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding LocationInfoWithLMSI SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "LocationInfoWithLMSI", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode locationInfo
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field locationInfo", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "locationInfo", content[offset:])
		// Decode nested CHOICE (LocationInfo)
		_, n_locationinfo, _, tlvErr_locationinfo := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_locationinfo != nil {
			return qualifyBERError(tlvErr_locationinfo, "locationInfo", "decoding", false)
		}
		if offset > len(content) || n_locationinfo < 0 || n_locationinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.LocationInfo.UnmarshalBER(content[offset:offset+n_locationinfo], ber.ChildDecodeOptions(opts, "locationInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "locationInfo", "decoding", false)
		}
		if offset > len(content) || n_locationinfo < 0 || n_locationinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_locationinfo
	}
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "lmsi", content[offset:])
				val_lmsi, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lmsi", "decoding", false)
				}
				tmp_lmsi := LMSI(val_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "LocationInfoWithLMSI", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "LocationInfoWithLMSI", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s913b50_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ForwardSMArg to BER format.
func (v *ForwardSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ForwardSMArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ForwardSMArg).MarshalBER, (*ForwardSMArg).marshalBER, 3)

}
func (v *ForwardSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalBER(ber.ChildEncodeOptions(opts, "sm-RP-DA")...)
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-DA", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_smrpda)
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalBER(ber.ChildEncodeOptions(opts, "sm-RP-OA")...)
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-OA", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_smrpoa)
	children = append(children, enc_smrpoa...)
	if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", false)
	}
	children = append(children, enc_smrpui...)
	if v.MoreMessagesToSend != nil {
		enc_moremessagestosend := ber.EncodeNull()
		children = append(children, enc_moremessagestosend...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s913b50_3, children, i, &base_); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s913b50_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ForwardSMArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ForwardSMArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ForwardSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardSMArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_smrpda, err := v.SmRPDA.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-DA", "encoding", true)
	}
	children = append(children, enc_smrpda...)
	enc_smrpoa, err := v.SmRPOA.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "sm-RP-OA", "encoding", true)
	}
	children = append(children, enc_smrpoa...)
	if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", true)
	}
	children = append(children, enc_smrpui...)
	if v.MoreMessagesToSend != nil {
		enc_moremessagestosend := ber.EncodeNull()
		children = append(children, enc_moremessagestosend...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s913b50_3, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s913b50_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ForwardSMArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ForwardSMArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ForwardSMArg from BER/DER format.
func (destination *ForwardSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ForwardSMArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ForwardSMArg)
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
			var probe ForwardSMArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s913b50_3, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ForwardSMArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ForwardSMArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ForwardSMArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode sm-RP-DA
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field sm-RP-DA", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-DA", content[offset:])
		// Decode nested CHOICE (SMRPDA)
		_, n_smrpda, _, tlvErr_smrpda := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_smrpda != nil {
			return qualifyBERError(tlvErr_smrpda, "sm-RP-DA", "decoding", false)
		}
		if offset > len(content) || n_smrpda < 0 || n_smrpda > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.SmRPDA.UnmarshalBER(content[offset:offset+n_smrpda], ber.ChildDecodeOptions(opts, "sm-RP-DA")...); unmErr != nil {
			return qualifyBERError(unmErr, "sm-RP-DA", "decoding", false)
		}
		if offset > len(content) || n_smrpda < 0 || n_smrpda > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_smrpda
	}
	// Decode sm-RP-OA
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field sm-RP-OA", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-OA", content[offset:])
		// Decode nested CHOICE (SMRPOA)
		_, n_smrpoa, _, tlvErr_smrpoa := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_smrpoa != nil {
			return qualifyBERError(tlvErr_smrpoa, "sm-RP-OA", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_smrpoa < 0 || n_smrpoa > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.SmRPOA.UnmarshalBER(content[offset:offset+n_smrpoa], ber.ChildDecodeOptions(opts, "sm-RP-OA")...); unmErr != nil {
			return qualifyBERError(unmErr, "sm-RP-OA", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_smrpoa < 0 || n_smrpoa > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_smrpoa
	}
	// Decode sm-RP-UI
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field sm-RP-UI", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "sm-RP-UI", content[offset:])
		val_smrpui, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "sm-RP-UI", "decoding", false)
		}
		v.SmRPUI = SignalInfo(val_smrpui)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode moreMessagesToSend
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "moreMessagesToSend", content[offset:])
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "moreMessagesToSend", "decoding", false)
				}
				v.MoreMessagesToSend = &struct{}{}
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardSMArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ForwardSMArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s913b50_3, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SMRPDA to BER format.
func (v *SMRPDA) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SMRPDA receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SMRPDA).MarshalBER, (*SMRPDA).marshalBER, 3)

}
func (v *SMRPDA) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SMRPDA) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SMRPDAChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SMRPDA: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 3 || len(*v.Imsi) > 8 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "imsi", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMRPDAChoiceLmsi:
		if v.Lmsi == nil {
			return nil, fmt.Errorf("%w: choice SMRPDA: lmsi is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "lmsi", "encoding", false)
		}
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "lmsi", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMRPDAChoiceRoamingNumber:
		if v.RoamingNumber == nil {
			return nil, fmt.Errorf("%w: choice SMRPDA: roamingNumber is nil", ber.ErrInvalidValue)
		}
		enc_2, encodeErr_enc_2 := ber.EncodeOctetString([]byte(*v.RoamingNumber))
		if encodeErr_enc_2 != nil {
			return nil, qualifyBERError(encodeErr_enc_2, "roamingNumber", "encoding", false)
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..9)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "roamingNumber", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SMRPDAChoiceServiceCentreAddressDA:
		if v.ServiceCentreAddressDA == nil {
			return nil, fmt.Errorf("%w: choice SMRPDA: serviceCentreAddressDA is nil", ber.ErrInvalidValue)
		}
		enc_3, encodeErr_enc_3 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressDA))
		if encodeErr_enc_3 != nil {
			return nil, qualifyBERError(encodeErr_enc_3, "serviceCentreAddressDA", "encoding", false)
		}
		if len(*v.ServiceCentreAddressDA) < 1 || len(*v.ServiceCentreAddressDA) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddressDA", "SIZE (1..20)", len(*v.ServiceCentreAddressDA)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "serviceCentreAddressDA", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	case SMRPDAChoiceNoSMRPDA:
		enc_4 := ber.EncodeNull()
		retagged_enc_4, tagErr_enc_4 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_4)
		if tagErr_enc_4 != nil {
			return nil, qualifyBERError(tagErr_enc_4, "noSM-RP-DA", "encoding", false)
		}
		enc_4 = retagged_enc_4
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMRPDA", v.Choice)
	}
}

// MarshalDER encodes SMRPDA to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SMRPDA) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMRPDA receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SMRPDAChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case SMRPDAChoiceLmsi:
			return nil, qualifyBERError(err, "lmsi", "encoding", true)
		case SMRPDAChoiceRoamingNumber:
			return nil, qualifyBERError(err, "roamingNumber", "encoding", true)
		case SMRPDAChoiceServiceCentreAddressDA:
			return nil, qualifyBERError(err, "serviceCentreAddressDA", "encoding", true)
		case SMRPDAChoiceNoSMRPDA:
			return nil, qualifyBERError(err, "noSM-RP-DA", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SMRPDA as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SMRPDA) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMRPDA from BER/DER format.
func (destination *SMRPDA) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SMRPDA destination is nil", ber.ErrInvalidValue)
	}
	v := new(SMRPDA)
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
				opts, v, &v.berReplayNode_, (*SMRPDA).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SMRPDA
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s913b50_4, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SMRPDA{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMRPDA CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMRPDA: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SMRPDA CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRPDA", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SMRPDA.noSM-RP-DA", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SMRPDAChoiceImsi
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
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMRPDAChoiceLmsi
		ber.MarkPreflightTarget(opts, "lmsi", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "lmsi", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "lmsi", "decoding", false)
		}
		tmp := LMSI(decVal)
		v.Lmsi = &tmp
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = SMRPDAChoiceRoamingNumber
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
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..9)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPDAChoiceServiceCentreAddressDA
		ber.MarkPreflightTarget(opts, "serviceCentreAddressDA", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "serviceCentreAddressDA", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "serviceCentreAddressDA", "decoding", false)
		}
		tmp := AddressString(decVal)
		v.ServiceCentreAddressDA = &tmp
		if len(*v.ServiceCentreAddressDA) < 1 || len(*v.ServiceCentreAddressDA) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddressDA", "SIZE (1..20)", len(*v.ServiceCentreAddressDA)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMRPDAChoiceNoSMRPDA
		ber.MarkPreflightTarget(opts, "noSM-RP-DA", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "noSM-RP-DA", "decoding", false)
		}
		_ = rawVal
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "noSM-RP-DA", "decoding", false)
		}
		v.NoSMRPDA = &struct{}{}
	} else {
		return fmt.Errorf("%w: unknown tag %s for SMRPDA CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes SMRPOA to BER format.
func (v *SMRPOA) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SMRPOA receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SMRPOA).MarshalBER, (*SMRPOA).marshalBER, 3)

}
func (v *SMRPOA) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SMRPOA) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SMRPOAChoiceMsisdn:
		if v.Msisdn == nil {
			return nil, fmt.Errorf("%w: choice SMRPOA: msisdn is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "msisdn", "encoding", false)
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "msisdn", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMRPOAChoiceServiceCentreAddressOA:
		if v.ServiceCentreAddressOA == nil {
			return nil, fmt.Errorf("%w: choice SMRPOA: serviceCentreAddressOA is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddressOA))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "serviceCentreAddressOA", "encoding", false)
		}
		if len(*v.ServiceCentreAddressOA) < 1 || len(*v.ServiceCentreAddressOA) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddressOA", "SIZE (1..20)", len(*v.ServiceCentreAddressOA)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "serviceCentreAddressOA", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SMRPOAChoiceNoSMRPOA:
		enc_2 := ber.EncodeNull()
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "noSM-RP-OA", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SMRPOA", v.Choice)
	}
}

// MarshalDER encodes SMRPOA to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SMRPOA) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SMRPOA receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SMRPOAChoiceMsisdn:
			return nil, qualifyBERError(err, "msisdn", "encoding", true)
		case SMRPOAChoiceServiceCentreAddressOA:
			return nil, qualifyBERError(err, "serviceCentreAddressOA", "encoding", true)
		case SMRPOAChoiceNoSMRPOA:
			return nil, qualifyBERError(err, "noSM-RP-OA", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SMRPOA as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SMRPOA) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SMRPOA from BER/DER format.
func (destination *SMRPOA) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SMRPOA destination is nil", ber.ErrInvalidValue)
	}
	v := new(SMRPOA)
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
				opts, v, &v.berReplayNode_, (*SMRPOA).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SMRPOA
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s913b50_5, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SMRPOA{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SMRPOA CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SMRPOA: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SMRPOA CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SMRPOA", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SMRPOA.noSM-RP-OA", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SMRPOAChoiceMsisdn
		ber.MarkPreflightTarget(opts, "msisdn", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "msisdn", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msisdn", "decoding", false)
		}
		tmp := ISDNAddressString(decVal)
		v.Msisdn = &tmp
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPOAChoiceServiceCentreAddressOA
		ber.MarkPreflightTarget(opts, "serviceCentreAddressOA", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "serviceCentreAddressOA", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "serviceCentreAddressOA", "decoding", false)
		}
		tmp := AddressString(decVal)
		v.ServiceCentreAddressOA = &tmp
		if len(*v.ServiceCentreAddressOA) < 1 || len(*v.ServiceCentreAddressOA) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddressOA", "SIZE (1..20)", len(*v.ServiceCentreAddressOA)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SMRPOAChoiceNoSMRPOA
		ber.MarkPreflightTarget(opts, "noSM-RP-OA", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "noSM-RP-OA", "decoding", false)
		}
		_ = rawVal
		if len(rawVal) != 0 {
			return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal)), "noSM-RP-OA", "decoding", false)
		}
		v.NoSMRPOA = &struct{}{}
	} else {
		return fmt.Errorf("%w: unknown tag %s for SMRPOA CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ReportSMDeliveryStatusArg to BER format.
func (v *ReportSMDeliveryStatusArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ReportSMDeliveryStatusArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ReportSMDeliveryStatusArg).MarshalBER, (*ReportSMDeliveryStatusArg).marshalBER, 3)

}
func (v *ReportSMDeliveryStatusArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", false)
	}
	children = append(children, enc_servicecentreaddress...)
	if v.SmDeliveryOutcome != nil {
		if int64(*v.SmDeliveryOutcome) != 0 && int64(*v.SmDeliveryOutcome) != 1 && int64(*v.SmDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(opts, s913b50_6, "20", "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.SmDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(*v.SmDeliveryOutcome))
		children = append(children, enc_smdeliveryoutcome...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s913b50_6, children, i, &base_); err != nil {
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
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s913b50_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ReportSMDeliveryStatusArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ReportSMDeliveryStatusArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ReportSMDeliveryStatusArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReportSMDeliveryStatusArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", true)
	}
	children = append(children, enc_servicecentreaddress...)
	if v.SmDeliveryOutcome != nil {
		if int64(*v.SmDeliveryOutcome) != 0 && int64(*v.SmDeliveryOutcome) != 1 && int64(*v.SmDeliveryOutcome) != 2 {
			if constraintErr := checkEncodedValue(nil, s913b50_6, "20", "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.SmDeliveryOutcome))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_smdeliveryoutcome := ber.EncodeEnumerated(int64(*v.SmDeliveryOutcome))
		children = append(children, enc_smdeliveryoutcome...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s913b50_6, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s913b50_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ReportSMDeliveryStatusArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ReportSMDeliveryStatusArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ReportSMDeliveryStatusArg from BER/DER format.
func (destination *ReportSMDeliveryStatusArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ReportSMDeliveryStatusArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ReportSMDeliveryStatusArg)

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
			var probe ReportSMDeliveryStatusArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s913b50_6, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReportSMDeliveryStatusArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ReportSMDeliveryStatusArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ReportSMDeliveryStatusArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReportSMDeliveryStatusArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field msisdn", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
		val_msisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msisdn", "decoding", false)
		}
		v.Msisdn = ISDNAddressString(val_msisdn)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field serviceCentreAddress", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "serviceCentreAddress", content[offset:])
		val_servicecentreaddress, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "serviceCentreAddress", "decoding", false)
		}
		v.ServiceCentreAddress = AddressString(val_servicecentreaddress)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode sm-DeliveryOutcome
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "sm-DeliveryOutcome", content[offset:])
				val_smdeliveryoutcome, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "sm-DeliveryOutcome", "decoding", false)
				}
				tmp_smdeliveryoutcome := SMDeliveryOutcome(val_smdeliveryoutcome)
				v.SmDeliveryOutcome = &tmp_smdeliveryoutcome
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if int64(*v.SmDeliveryOutcome) != 0 && int64(*v.SmDeliveryOutcome) != 1 && int64(*v.SmDeliveryOutcome) != 2 {
					if constraintErr := checkDecodedValue(opts, s913b50_6, "20", "sm-DeliveryOutcome", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.SmDeliveryOutcome))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ReportSMDeliveryStatusArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ReportSMDeliveryStatusArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s913b50_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes AlertServiceCentreArg to BER format.
func (v *AlertServiceCentreArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: AlertServiceCentreArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*AlertServiceCentreArg).MarshalBER, (*AlertServiceCentreArg).marshalBER, 3)

}
func (v *AlertServiceCentreArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", false)
	}
	children = append(children, enc_servicecentreaddress...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s913b50_7, children, i, &base_); err != nil {
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
func (v *AlertServiceCentreArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes AlertServiceCentreArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *AlertServiceCentreArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AlertServiceCentreArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", true)
	}
	children = append(children, enc_servicecentreaddress...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s913b50_7, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AlertServiceCentreArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *AlertServiceCentreArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes AlertServiceCentreArg from BER/DER format.
func (destination *AlertServiceCentreArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: AlertServiceCentreArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(AlertServiceCentreArg)

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
			var probe AlertServiceCentreArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s913b50_7, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = AlertServiceCentreArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*AlertServiceCentreArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding AlertServiceCentreArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AlertServiceCentreArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field msisdn", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
		val_msisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msisdn", "decoding", false)
		}
		v.Msisdn = ISDNAddressString(val_msisdn)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode serviceCentreAddress
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field serviceCentreAddress", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "serviceCentreAddress", content[offset:])
		val_servicecentreaddress, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "serviceCentreAddress", "decoding", false)
		}
		v.ServiceCentreAddress = AddressString(val_servicecentreaddress)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "AlertServiceCentreArg", Cause: extErr_}
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

// MarshalBER encodes InformServiceCentreArg to BER format.
func (v *InformServiceCentreArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: InformServiceCentreArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*InformServiceCentreArg).MarshalBER, (*InformServiceCentreArg).marshalBER, 3)

}
func (v *InformServiceCentreArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.StoredMSISDN != nil {
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_storedmsisdn, encodeErr_enc_storedmsisdn := ber.EncodeOctetString([]byte(*v.StoredMSISDN))
		if encodeErr_enc_storedmsisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_storedmsisdn, "storedMSISDN", "encoding", false)
		}
		children = append(children, enc_storedmsisdn...)
	}
	if v.MwStatus != nil {
		namedBits_MwStatus, namedBitErr_ := normalizeNamedBits(*v.MwStatus, []ber.NamedBitSizeSet{{{Min: 6, Max: 6}}}, opts, "mw-Status", s913b50_8)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_MwStatus.Bytes, namedBits_MwStatus.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mw-Status", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:757
		if namedBits_MwStatus.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_MwStatus).BitLength < 6 || (namedBits_MwStatus).BitLength > 6 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "mw-Status", "SIZE (6)", namedBitObservedLength(namedBits_MwStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mwstatus, encodeErr_enc_mwstatus := ber.EncodeBitString(namedBits_MwStatus.Bytes, ber.UnusedBitCount(namedBits_MwStatus.BitLength))
		if encodeErr_enc_mwstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_mwstatus, "mw-Status", "encoding", false)
		}
		children = append(children, enc_mwstatus...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s913b50_8, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s913b50_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *InformServiceCentreArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes InformServiceCentreArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *InformServiceCentreArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InformServiceCentreArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.StoredMSISDN != nil {
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_storedmsisdn, encodeErr_enc_storedmsisdn := ber.EncodeOctetString([]byte(*v.StoredMSISDN))
		if encodeErr_enc_storedmsisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_storedmsisdn, "storedMSISDN", "encoding", true)
		}
		children = append(children, enc_storedmsisdn...)
	}
	if v.MwStatus != nil {
		namedBits_MwStatus, namedBitErr_ := normalizeNamedBits(*v.MwStatus, []ber.NamedBitSizeSet{{{Min: 6, Max: 6}}}, nil, "mw-Status", s913b50_8)
		if namedBitErr_ != nil {
			return nil, namedBitErr_
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_MwStatus.Bytes, namedBits_MwStatus.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "mw-Status", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:757
		if namedBits_MwStatus.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_MwStatus).BitLength < 6 || (namedBits_MwStatus).BitLength > 6 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "mw-Status", "SIZE (6)", namedBitObservedLength(namedBits_MwStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mwstatus, encodeErr_enc_mwstatus := encodeEditionBitString(namedBits_MwStatus.Bytes, namedBits_MwStatus.BitLength)
		if encodeErr_enc_mwstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_mwstatus, "mw-Status", "encoding", true)
		}
		children = append(children, enc_mwstatus...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s913b50_8, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s913b50_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding InformServiceCentreArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *InformServiceCentreArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes InformServiceCentreArg from BER/DER format.
func (destination *InformServiceCentreArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: InformServiceCentreArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(InformServiceCentreArg)

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
			var probe InformServiceCentreArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s913b50_8, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = InformServiceCentreArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*InformServiceCentreArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding InformServiceCentreArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InformServiceCentreArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode storedMSISDN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "storedMSISDN", content[offset:])
				val_storedmsisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "storedMSISDN", "decoding", false)
				}
				tmp_storedmsisdn := ISDNAddressString(val_storedmsisdn)
				v.StoredMSISDN = &tmp_storedmsisdn
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "storedMSISDN", "SIZE (1..9)", len(*v.StoredMSISDN)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.StoredMSISDN) < 1 || len(*v.StoredMSISDN) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "storedMSISDN", "SIZE (1..20)", len(*v.StoredMSISDN)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode mw-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "mw-Status", content[offset:])
				bsBytes_mwstatus, bsUnused_mwstatus, n, err := ber.DecodeBitString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mw-Status", "decoding", false)
				}
				bsBitLength_mwstatus, bsLenErr_mwstatus := ber.BitStringBitLength(len(bsBytes_mwstatus), bsUnused_mwstatus)
				if bsLenErr_mwstatus != nil {
					return qualifyBERError(bsLenErr_mwstatus, "mw-Status", "decoding", false)
				}
				tmp_mwstatus := runtime.BitString{Bytes: bsBytes_mwstatus, BitLength: bsBitLength_mwstatus}
				v.MwStatus = &tmp_mwstatus
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				*v.MwStatus = keepEditionBitLength(*v.MwStatus, []ber.NamedBitSizeSet{{{Min: 6, Max: 6}}}, opts...)
				if (*v.MwStatus).BitLength < 6 || (*v.MwStatus).BitLength > 6 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "mw-Status", "SIZE (6)", (*v.MwStatus).BitLength); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "InformServiceCentreArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 3) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "InformServiceCentreArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s913b50_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes ReadyForSMArg to BER format.
func (v *ReadyForSMArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ReadyForSMArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ReadyForSMArg).MarshalBER, (*ReadyForSMArg).marshalBER, 3)

}
func (v *ReadyForSMArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s913b50_9, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if int64(v.AlertReason) != 0 && int64(v.AlertReason) != 1 {
		if constraintErr := checkEncodedValue(opts, s913b50_9, "20", "alertReason", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.AlertReason))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_alertreason := ber.EncodeEnumerated(int64(v.AlertReason))
	children = append(children, enc_alertreason...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s913b50_9, children, i, &base_); err != nil {
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
func (v *ReadyForSMArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ReadyForSMArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ReadyForSMArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ReadyForSMArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s913b50_9, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if int64(v.AlertReason) != 0 && int64(v.AlertReason) != 1 {
		if constraintErr := checkEncodedValue(nil, s913b50_9, "20", "alertReason", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.AlertReason))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_alertreason := ber.EncodeEnumerated(int64(v.AlertReason))
	children = append(children, enc_alertreason...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s913b50_9, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ReadyForSMArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ReadyForSMArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ReadyForSMArg from BER/DER format.
func (destination *ReadyForSMArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ReadyForSMArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ReadyForSMArg)
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
			var probe ReadyForSMArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s913b50_9, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ReadyForSMArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ReadyForSMArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ReadyForSMArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ReadyForSMArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field imsi", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("%w: expected tag [%s %d] for imsi, got %s", ber.ErrUnexpectedElement, "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "imsi", content[offset:])
		decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "imsi", "decoding", false)
		}
		if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_imsi), "imsi", "decoding", false)
		}
		decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "imsi", "decoding", false)
		}
		v.Imsi = IMSI(decVal_imsi)
		if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_imsi
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s913b50_9, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode alertReason
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field alertReason", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "alertReason", content[offset:])
		val_alertreason, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "alertReason", "decoding", false)
		}
		v.AlertReason = AlertReason(val_alertreason)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.AlertReason) != 0 && int64(v.AlertReason) != 1 {
			if constraintErr := checkDecodedValue(opts, s913b50_9, "20", "alertReason", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.AlertReason))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ReadyForSMArg", Cause: extErr_}
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
	s913b50_0 = "MAP-SM-DataTypes.RoutingInfoForSM-Arg"
	s913b50_1 = "MAP-SM-DataTypes.RoutingInfoForSM-Res"
	s913b50_2 = "MAP-SM-DataTypes.LocationInfoWithLMSI"
	s913b50_3 = "MAP-SM-DataTypes.ForwardSM-Arg"
	s913b50_4 = "MAP-SM-DataTypes.SM-RP-DA"
	s913b50_5 = "MAP-SM-DataTypes.SM-RP-OA"
	s913b50_6 = "MAP-SM-DataTypes.ReportSM-DeliveryStatusArg"
	s913b50_7 = "MAP-SM-DataTypes.AlertServiceCentreArg"
	s913b50_8 = "MAP-SM-DataTypes.InformServiceCentreArg"
	s913b50_9 = "MAP-SM-DataTypes.ReadyForSM-Arg"
)
