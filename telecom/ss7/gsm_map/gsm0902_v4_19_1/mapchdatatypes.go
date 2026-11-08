// Code generated from ASN.1 module "MAP-CH-DataTypes". DO NOT EDIT.

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

// CUGCheckInfo represents the ASN.1 type CUG-CheckInfo (SEQUENCE).
type CUGCheckInfo struct {
	CugInterlock      CUGInterlock `asn1:""`
	CugOutgoingAccess *struct{}    `asn1:",optional" json:"CugOutgoingAccess,omitempty"`
	ExtCount_         int64        `asn1:"-" json:"-"`
	ExtPresent_       []bool       `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// NumberOfForwarding represents the ASN.1 type NumberOfForwarding (INTEGER).
type NumberOfForwarding = int64

// SendRoutingInfoArg represents the ASN.1 type SendRoutingInfoArg (SEQUENCE).
type SendRoutingInfoArg struct {
	Msisdn             ISDNAddressString   `asn1:"tag:0,context,implicit"`
	CugCheckInfo       *CUGCheckInfo       `asn1:"tag:1,context,implicit,optional" json:"CugCheckInfo,omitempty"`
	NumberOfForwarding *NumberOfForwarding `asn1:"tag:2,context,implicit,optional" json:"NumberOfForwarding,omitempty"`
	NetworkSignalInfo  *ExternalSignalInfo `asn1:"tag:10,context,implicit,optional" json:"NetworkSignalInfo,omitempty"`
	ExtCount_          int64               `asn1:"-" json:"-"`
	ExtPresent_        []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SendRoutingInfoRes represents the ASN.1 type SendRoutingInfoRes (SEQUENCE).
type SendRoutingInfoRes struct {
	Imsi         IMSI          `asn1:""`
	RoutingInfo  RoutingInfo   `asn1:""`
	CugCheckInfo *CUGCheckInfo `asn1:",optional" json:"CugCheckInfo,omitempty"`
	ExtCount_    int64         `asn1:"-" json:"-"`
	ExtPresent_  []bool        `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// RoutingInfo choice constants.
const (
	RoutingInfoChoiceRoamingNumber  = 1
	RoutingInfoChoiceForwardingData = 2
)

// RoutingInfo represents the ASN.1 CHOICE type RoutingInfo.
type RoutingInfo struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode    `json:"-"`
	RoamingNumber  *ISDNAddressString `json:"RoamingNumber,omitempty"`
	ForwardingData *ForwardingData    `json:"ForwardingData,omitempty"`
}

// NewRoutingInfoRoamingNumber creates a RoutingInfo with the roamingNumber alternative.
func NewRoutingInfoRoamingNumber(v ISDNAddressString) RoutingInfo {
	return RoutingInfo{
		Choice:        RoutingInfoChoiceRoamingNumber,
		RoamingNumber: &v,
	}
}

// NewRoutingInfoForwardingData creates a RoutingInfo with the forwardingData alternative.
func NewRoutingInfoForwardingData(v ForwardingData) RoutingInfo {
	return RoutingInfo{
		Choice:         RoutingInfoChoiceForwardingData,
		ForwardingData: &v,
	}
}

// ProvideRoamingNumberArg represents the ASN.1 type ProvideRoamingNumberArg (SEQUENCE).
type ProvideRoamingNumberArg struct {
	Imsi                  IMSI                `asn1:"tag:0,context,implicit"`
	MscNumber             *ISDNAddressString  `asn1:"tag:1,context,implicit,optional" json:"MscNumber,omitempty"`
	Msisdn                *ISDNAddressString  `asn1:"tag:2,context,implicit,optional" json:"Msisdn,omitempty"`
	PreviousRoamingNumber *ISDNAddressString  `asn1:"tag:3,context,implicit,optional" json:"PreviousRoamingNumber,omitempty"`
	Lmsi                  *LMSI               `asn1:"tag:4,context,implicit,optional" json:"Lmsi,omitempty"`
	GsmBearerCapability   *ExternalSignalInfo `asn1:"tag:5,context,implicit,optional" json:"GsmBearerCapability,omitempty"`
	NetworkSignalInfo     *ExternalSignalInfo `asn1:"tag:6,context,implicit,optional" json:"NetworkSignalInfo,omitempty"`
	ExtCount_             int64               `asn1:"-" json:"-"`
	ExtPresent_           []bool              `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes CUGCheckInfo to BER format.
func (v *CUGCheckInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CUGCheckInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CUGCheckInfo).MarshalBER, (*CUGCheckInfo).marshalBER, 3)

}
func (v *CUGCheckInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-Interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(v.CugInterlock))
	if encodeErr_enc_cuginterlock != nil {
		return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", false)
	}
	children = append(children, enc_cuginterlock...)
	if v.CugOutgoingAccess != nil {
		enc_cugoutgoingaccess := ber.EncodeNull()
		children = append(children, enc_cugoutgoingaccess...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s1e3274_0, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s1e3274_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CUGCheckInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CUGCheckInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CUGCheckInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CUGCheckInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-Interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(v.CugInterlock))
	if encodeErr_enc_cuginterlock != nil {
		return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", true)
	}
	children = append(children, enc_cuginterlock...)
	if v.CugOutgoingAccess != nil {
		enc_cugoutgoingaccess := ber.EncodeNull()
		children = append(children, enc_cugoutgoingaccess...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s1e3274_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s1e3274_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CUGCheckInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CUGCheckInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CUGCheckInfo from BER/DER format.
func (destination *CUGCheckInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CUGCheckInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(CUGCheckInfo)
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
			var probe CUGCheckInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s1e3274_0, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CUGCheckInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CUGCheckInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CUGCheckInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGCheckInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cug-Interlock
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cug-Interlock", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cug-Interlock", content[offset:])
		val_cuginterlock, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cug-Interlock", "decoding", false)
		}
		v.CugInterlock = CUGInterlock(val_cuginterlock)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-Interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cug-OutgoingAccess
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "cug-OutgoingAccess", content[offset:])
				n, err := ber.DecodeNull(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cug-OutgoingAccess", "decoding", false)
				}
				v.CugOutgoingAccess = &struct{}{}
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
			return &ber.DecodeError{Offset: offset, TypeName: "CUGCheckInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CUGCheckInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s1e3274_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SendRoutingInfoArg to BER format.
func (v *SendRoutingInfoArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendRoutingInfoArg).MarshalBER, (*SendRoutingInfoArg).marshalBER, 3)

}
func (v *SendRoutingInfoArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
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
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER(ber.ChildEncodeOptions(opts, "cug-CheckInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "cug-CheckInfo", "encoding", false)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, qualifyBERError(tagErr_enc_cugcheckinfo, "cug-CheckInfo", "encoding", false)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_cugcheckinfo)
		children = append(children, enc_cugcheckinfo...)
	}
	if v.NumberOfForwarding != nil {
		if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
			if constraintErr := checkEncodedValue(opts, s1e3274_1, "51.4", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		retagged_enc_numberofforwarding, tagErr_enc_numberofforwarding := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_numberofforwarding)
		if tagErr_enc_numberofforwarding != nil {
			return nil, qualifyBERError(tagErr_enc_numberofforwarding, "numberOfForwarding", "encoding", false)
		}
		enc_numberofforwarding = retagged_enc_numberofforwarding
		children = append(children, enc_numberofforwarding...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER(ber.ChildEncodeOptions(opts, "networkSignalInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "networkSignalInfo", "encoding", false)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_networksignalinfo, "networkSignalInfo", "encoding", false)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_networksignalinfo)
		children = append(children, enc_networksignalinfo...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s1e3274_1, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s1e3274_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendRoutingInfoArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendRoutingInfoArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendRoutingInfoArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
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
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cug-CheckInfo", "encoding", true)
		}
		retagged_enc_cugcheckinfo, tagErr_enc_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cugcheckinfo)
		if tagErr_enc_cugcheckinfo != nil {
			return nil, qualifyBERError(tagErr_enc_cugcheckinfo, "cug-CheckInfo", "encoding", true)
		}
		enc_cugcheckinfo = retagged_enc_cugcheckinfo
		children = append(children, enc_cugcheckinfo...)
	}
	if v.NumberOfForwarding != nil {
		if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
			if constraintErr := checkEncodedValue(nil, s1e3274_1, "51.4", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		retagged_enc_numberofforwarding, tagErr_enc_numberofforwarding := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_numberofforwarding)
		if tagErr_enc_numberofforwarding != nil {
			return nil, qualifyBERError(tagErr_enc_numberofforwarding, "numberOfForwarding", "encoding", true)
		}
		enc_numberofforwarding = retagged_enc_numberofforwarding
		children = append(children, enc_numberofforwarding...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "networkSignalInfo", "encoding", true)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_networksignalinfo, "networkSignalInfo", "encoding", true)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		children = append(children, enc_networksignalinfo...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s1e3274_1, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s1e3274_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SendRoutingInfoArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendRoutingInfoArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendRoutingInfoArg from BER/DER format.
func (destination *SendRoutingInfoArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendRoutingInfoArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendRoutingInfoArg)

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
			var probe SendRoutingInfoArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s1e3274_1, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendRoutingInfoArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendRoutingInfoArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInfoArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInfoArg", Cause: ber.ErrExtraData}
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
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "cug-CheckInfo", content[offset:])
				decodedTag_cugcheckinfo, n_cugcheckinfo, rawVal_cugcheckinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cug-CheckInfo", "decoding", false)
				}
				if decodedTag_cugcheckinfo.Class != tag.ClassContextSpecific || decodedTag_cugcheckinfo.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_cugcheckinfo), "cug-CheckInfo", "decoding", false)
				}
				if decodedTag_cugcheckinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_cugcheckinfo), "cug-CheckInfo", "decoding", false)
				}
				_ = rawVal_cugcheckinfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_cugcheckinfo, reconstructionErr_cugcheckinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_cugcheckinfo])
				if reconstructionErr_cugcheckinfo != nil {
					return qualifyBERError(reconstructionErr_cugcheckinfo, "cug-CheckInfo", "decoding", false)
				}
				var dec_cugcheckinfo CUGCheckInfo
				if unmErr := dec_cugcheckinfo.UnmarshalBER(reconstructed_cugcheckinfo, ber.ChildDecodeOptions(opts, "cug-CheckInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "cug-CheckInfo", "decoding", false)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugcheckinfo
			}
		}
	}
	// Decode numberOfForwarding
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "numberOfForwarding", content[offset:])
				decodedTag_numberofforwarding, n_numberofforwarding, rawVal_numberofforwarding, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "numberOfForwarding", "decoding", false)
				}
				if decodedTag_numberofforwarding.Class != tag.ClassContextSpecific || decodedTag_numberofforwarding.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_numberofforwarding), "numberOfForwarding", "decoding", false)
				}
				if decodedTag_numberofforwarding.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_numberofforwarding), "numberOfForwarding", "decoding", false)
				}
				decVal_numberofforwarding, intErr := ber.DecodeIntegerValue(rawVal_numberofforwarding)
				if intErr != nil {
					return qualifyBERError(intErr, "numberOfForwarding", "decoding", false)
				}
				tmp_numberofforwarding := NumberOfForwarding(decVal_numberofforwarding)
				v.NumberOfForwarding = &tmp_numberofforwarding
				if offset < 0 || offset >
					len(content) || n_numberofforwarding < 0 || n_numberofforwarding >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_numberofforwarding
				if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
					if constraintErr := checkDecodedValue(opts, s1e3274_1, "51.4", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode networkSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "networkSignalInfo", content[offset:])
				decodedTag_networksignalinfo, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "networkSignalInfo", "decoding", false)
				}
				if decodedTag_networksignalinfo.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_networksignalinfo), "networkSignalInfo", "decoding", false)
				}
				if decodedTag_networksignalinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo), "networkSignalInfo", "decoding", false)
				}
				_ = rawVal_networksignalinfo
				if offset < 0 || offset >
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_networksignalinfo, reconstructionErr_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_networksignalinfo])
				if reconstructionErr_networksignalinfo != nil {
					return qualifyBERError(reconstructionErr_networksignalinfo, "networkSignalInfo", "decoding", false)
				}
				var dec_networksignalinfo ExternalSignalInfo
				if unmErr := dec_networksignalinfo.UnmarshalBER(reconstructed_networksignalinfo, ber.ChildDecodeOptions(opts, "networkSignalInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "networkSignalInfo", "decoding", false)
				}
				v.NetworkSignalInfo = &dec_networksignalinfo
				if offset < 0 || offset >
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_networksignalinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s1e3274_1, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SendRoutingInfoRes to BER format.
func (v *SendRoutingInfoRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendRoutingInfoRes).MarshalBER, (*SendRoutingInfoRes).marshalBER, 3)

}
func (v *SendRoutingInfoRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	enc_routinginfo, err := v.RoutingInfo.MarshalBER(ber.ChildEncodeOptions(opts, "routingInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "routingInfo", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_routinginfo)
	children = append(children, enc_routinginfo...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalBER(ber.ChildEncodeOptions(opts, "cug-CheckInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "cug-CheckInfo", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_cugcheckinfo)
		children = append(children, enc_cugcheckinfo...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s1e3274_2, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s1e3274_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendRoutingInfoRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendRoutingInfoRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendRoutingInfoRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	enc_routinginfo, err := v.RoutingInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "routingInfo", "encoding", true)
	}
	children = append(children, enc_routinginfo...)
	if v.CugCheckInfo != nil {
		enc_cugcheckinfo, err := v.CugCheckInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cug-CheckInfo", "encoding", true)
		}
		children = append(children, enc_cugcheckinfo...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s1e3274_2, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s1e3274_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SendRoutingInfoRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendRoutingInfoRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendRoutingInfoRes from BER/DER format.
func (destination *SendRoutingInfoRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendRoutingInfoRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendRoutingInfoRes)

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
			var probe SendRoutingInfoRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s1e3274_2, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendRoutingInfoRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendRoutingInfoRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInfoRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInfoRes", Cause: ber.ErrExtraData}
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
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode routingInfo
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field routingInfo", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "routingInfo", content[offset:])
		// Decode nested CHOICE (RoutingInfo)
		_, n_routinginfo, _, tlvErr_routinginfo := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_routinginfo != nil {
			return qualifyBERError(tlvErr_routinginfo, "routingInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_routinginfo < 0 || n_routinginfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.RoutingInfo.UnmarshalBER(content[offset:offset+n_routinginfo], ber.ChildDecodeOptions(opts, "routingInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "routingInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_routinginfo < 0 || n_routinginfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_routinginfo
	}
	// Decode cug-CheckInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "cug-CheckInfo", content[offset:])
				// Decode nested SEQUENCE (CUGCheckInfo)
				_, n_cugcheckinfo, _, tlvErr_cugcheckinfo := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_cugcheckinfo != nil {
					return qualifyBERError(tlvErr_cugcheckinfo, "cug-CheckInfo", "decoding", false)
				}
				var dec_cugcheckinfo CUGCheckInfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_cugcheckinfo.UnmarshalBER(content[offset:offset+n_cugcheckinfo], ber.ChildDecodeOptions(opts, "cug-CheckInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "cug-CheckInfo", "decoding", false)
				}
				v.CugCheckInfo = &dec_cugcheckinfo
				if offset < 0 || offset >
					len(content) || n_cugcheckinfo < 0 || n_cugcheckinfo > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugcheckinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s1e3274_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes RoutingInfo to BER format.
func (v *RoutingInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RoutingInfo).MarshalBER, (*RoutingInfo).marshalBER, 3)

}
func (v *RoutingInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *RoutingInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case RoutingInfoChoiceRoamingNumber:
		if v.RoamingNumber == nil {
			return nil, fmt.Errorf("%w: choice RoutingInfo: roamingNumber is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.RoamingNumber))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "roamingNumber", "encoding", false)
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..9)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case RoutingInfoChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("%w: choice RoutingInfo: forwardingData is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ForwardingData.MarshalBER(ber.ChildEncodeOptions(opts, "forwardingData")...)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingData", "encoding", false)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for RoutingInfo", v.Choice)
	}
}

// MarshalDER encodes RoutingInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RoutingInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RoutingInfo receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case RoutingInfoChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("%w: choice RoutingInfo: forwardingData is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ForwardingData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "forwardingData", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "forwardingData", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case RoutingInfoChoiceRoamingNumber:
			return nil, qualifyBERError(err, "roamingNumber", "encoding", true)
		case RoutingInfoChoiceForwardingData:
			return nil, qualifyBERError(err, "forwardingData", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding RoutingInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *RoutingInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RoutingInfo from BER/DER format.
func (destination *RoutingInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RoutingInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(RoutingInfo)
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
				opts, v, &v.berReplayNode_, (*RoutingInfo).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe RoutingInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s1e3274_3, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RoutingInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for RoutingInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for RoutingInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding RoutingInfo CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "RoutingInfo", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "RoutingInfo.forwardingData", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = RoutingInfoChoiceRoamingNumber
		ber.MarkPreflightTarget(opts, "roamingNumber", choiceData)
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return qualifyBERError(osErr, "roamingNumber", "decoding", false)
		}
		tmp := ISDNAddressString(decVal)
		v.RoamingNumber = &tmp
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..9)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = RoutingInfoChoiceForwardingData
		ber.MarkPreflightTarget(opts, "forwardingData", choiceData)
		var dec ForwardingData
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "forwardingData")...); unmErr != nil {
			return qualifyBERError(unmErr, "forwardingData", "decoding", false)
		}
		v.ForwardingData = &dec
	} else {
		return fmt.Errorf("%w: unknown tag %s for RoutingInfo CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ProvideRoamingNumberArg to BER format.
func (v *ProvideRoamingNumberArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ProvideRoamingNumberArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ProvideRoamingNumberArg).MarshalBER, (*ProvideRoamingNumberArg).marshalBER, 3)

}
func (v *ProvideRoamingNumberArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
	if v.MscNumber != nil {
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscnumber, encodeErr_enc_mscnumber := ber.EncodeOctetString([]byte(*v.MscNumber))
		if encodeErr_enc_mscnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_mscnumber, "msc-Number", "encoding", false)
		}
		retagged_enc_mscnumber, tagErr_enc_mscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mscnumber)
		if tagErr_enc_mscnumber != nil {
			return nil, qualifyBERError(tagErr_enc_mscnumber, "msc-Number", "encoding", false)
		}
		enc_mscnumber = retagged_enc_mscnumber
		children = append(children, enc_mscnumber...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.PreviousRoamingNumber != nil {
		if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "previousRoamingNumber", "SIZE (1..9)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "previousRoamingNumber", "SIZE (1..20)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_previousroamingnumber, encodeErr_enc_previousroamingnumber := ber.EncodeOctetString([]byte(*v.PreviousRoamingNumber))
		if encodeErr_enc_previousroamingnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_previousroamingnumber, "previousRoamingNumber", "encoding", false)
		}
		retagged_enc_previousroamingnumber, tagErr_enc_previousroamingnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_previousroamingnumber)
		if tagErr_enc_previousroamingnumber != nil {
			return nil, qualifyBERError(tagErr_enc_previousroamingnumber, "previousRoamingNumber", "encoding", false)
		}
		enc_previousroamingnumber = retagged_enc_previousroamingnumber
		children = append(children, enc_previousroamingnumber...)
	}
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", false)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, qualifyBERError(tagErr_enc_lmsi, "lmsi", "encoding", false)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalBER(ber.ChildEncodeOptions(opts, "gsm-BearerCapability")...)
		if err != nil {
			return nil, qualifyBERError(err, "gsm-BearerCapability", "encoding", false)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, qualifyBERError(tagErr_enc_gsmbearercapability, "gsm-BearerCapability", "encoding", false)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_gsmbearercapability)
		children = append(children, enc_gsmbearercapability...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER(ber.ChildEncodeOptions(opts, "networkSignalInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "networkSignalInfo", "encoding", false)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_networksignalinfo, "networkSignalInfo", "encoding", false)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_networksignalinfo)
		children = append(children, enc_networksignalinfo...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s1e3274_4, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s1e3274_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ProvideRoamingNumberArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ProvideRoamingNumberArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ProvideRoamingNumberArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ProvideRoamingNumberArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
	if v.MscNumber != nil {
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscnumber, encodeErr_enc_mscnumber := ber.EncodeOctetString([]byte(*v.MscNumber))
		if encodeErr_enc_mscnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_mscnumber, "msc-Number", "encoding", true)
		}
		retagged_enc_mscnumber, tagErr_enc_mscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mscnumber)
		if tagErr_enc_mscnumber != nil {
			return nil, qualifyBERError(tagErr_enc_mscnumber, "msc-Number", "encoding", true)
		}
		enc_mscnumber = retagged_enc_mscnumber
		children = append(children, enc_mscnumber...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.PreviousRoamingNumber != nil {
		if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "previousRoamingNumber", "SIZE (1..9)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "previousRoamingNumber", "SIZE (1..20)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_previousroamingnumber, encodeErr_enc_previousroamingnumber := ber.EncodeOctetString([]byte(*v.PreviousRoamingNumber))
		if encodeErr_enc_previousroamingnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_previousroamingnumber, "previousRoamingNumber", "encoding", true)
		}
		retagged_enc_previousroamingnumber, tagErr_enc_previousroamingnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_previousroamingnumber)
		if tagErr_enc_previousroamingnumber != nil {
			return nil, qualifyBERError(tagErr_enc_previousroamingnumber, "previousRoamingNumber", "encoding", true)
		}
		enc_previousroamingnumber = retagged_enc_previousroamingnumber
		children = append(children, enc_previousroamingnumber...)
	}
	if v.Lmsi != nil {
		if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsi, encodeErr_enc_lmsi := ber.EncodeOctetString([]byte(*v.Lmsi))
		if encodeErr_enc_lmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsi, "lmsi", "encoding", true)
		}
		retagged_enc_lmsi, tagErr_enc_lmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lmsi)
		if tagErr_enc_lmsi != nil {
			return nil, qualifyBERError(tagErr_enc_lmsi, "lmsi", "encoding", true)
		}
		enc_lmsi = retagged_enc_lmsi
		children = append(children, enc_lmsi...)
	}
	if v.GsmBearerCapability != nil {
		enc_gsmbearercapability, err := v.GsmBearerCapability.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "gsm-BearerCapability", "encoding", true)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, qualifyBERError(tagErr_enc_gsmbearercapability, "gsm-BearerCapability", "encoding", true)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		children = append(children, enc_gsmbearercapability...)
	}
	if v.NetworkSignalInfo != nil {
		enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "networkSignalInfo", "encoding", true)
		}
		retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_networksignalinfo)
		if tagErr_enc_networksignalinfo != nil {
			return nil, qualifyBERError(tagErr_enc_networksignalinfo, "networkSignalInfo", "encoding", true)
		}
		enc_networksignalinfo = retagged_enc_networksignalinfo
		children = append(children, enc_networksignalinfo...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s1e3274_4, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s1e3274_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ProvideRoamingNumberArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ProvideRoamingNumberArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ProvideRoamingNumberArg from BER/DER format.
func (destination *ProvideRoamingNumberArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ProvideRoamingNumberArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(ProvideRoamingNumberArg)

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
			var probe ProvideRoamingNumberArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s1e3274_4, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ProvideRoamingNumberArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ProvideRoamingNumberArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ProvideRoamingNumberArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideRoamingNumberArg", Cause: ber.ErrExtraData}
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
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode msc-Number
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "msc-Number", content[offset:])
				decodedTag_mscnumber, n_mscnumber, rawVal_mscnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msc-Number", "decoding", false)
				}
				if decodedTag_mscnumber.Class != tag.ClassContextSpecific || decodedTag_mscnumber.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_mscnumber), "msc-Number", "decoding", false)
				}
				decVal_mscnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mscnumber.Constructed, rawVal_mscnumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msc-Number", "decoding", false)
				}
				tmp_mscnumber := ISDNAddressString(decVal_mscnumber)
				v.MscNumber = &tmp_mscnumber
				if offset < 0 || offset >
					len(content) || n_mscnumber < 0 || n_mscnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mscnumber
				if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msc-Number", "SIZE (1..9)", len(*v.MscNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msc-Number", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msisdn", "decoding", false)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_msisdn), "msisdn", "decoding", false)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msisdn", "decoding", false)
				}
				tmp_msisdn := ISDNAddressString(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode previousRoamingNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "previousRoamingNumber", content[offset:])
				decodedTag_previousroamingnumber, n_previousroamingnumber, rawVal_previousroamingnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "previousRoamingNumber", "decoding", false)
				}
				if decodedTag_previousroamingnumber.Class != tag.ClassContextSpecific || decodedTag_previousroamingnumber.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_previousroamingnumber), "previousRoamingNumber", "decoding", false)
				}
				decVal_previousroamingnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_previousroamingnumber.Constructed, rawVal_previousroamingnumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "previousRoamingNumber", "decoding", false)
				}
				tmp_previousroamingnumber := ISDNAddressString(decVal_previousroamingnumber)
				v.PreviousRoamingNumber = &tmp_previousroamingnumber
				if offset < 0 || offset >
					len(content) || n_previousroamingnumber < 0 || n_previousroamingnumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_previousroamingnumber
				if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "previousRoamingNumber", "SIZE (1..9)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "previousRoamingNumber", "SIZE (1..20)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "lmsi", content[offset:])
				decodedTag_lmsi, n_lmsi, rawVal_lmsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lmsi", "decoding", false)
				}
				if decodedTag_lmsi.Class != tag.ClassContextSpecific || decodedTag_lmsi.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_lmsi), "lmsi", "decoding", false)
				}
				decVal_lmsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lmsi.Constructed, rawVal_lmsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lmsi", "decoding", false)
				}
				tmp_lmsi := LMSI(decVal_lmsi)
				v.Lmsi = &tmp_lmsi
				if offset < 0 || offset >
					len(content) || n_lmsi < 0 || n_lmsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lmsi
				if len(*v.Lmsi) < 4 || len(*v.Lmsi) > 4 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s1e3274_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "lmsi", "SIZE (4)", len(*v.Lmsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode gsm-BearerCapability
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "gsm-BearerCapability", content[offset:])
				decodedTag_gsmbearercapability, n_gsmbearercapability, rawVal_gsmbearercapability, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "gsm-BearerCapability", "decoding", false)
				}
				if decodedTag_gsmbearercapability.Class != tag.ClassContextSpecific || decodedTag_gsmbearercapability.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_gsmbearercapability), "gsm-BearerCapability", "decoding", false)
				}
				if decodedTag_gsmbearercapability.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_gsmbearercapability), "gsm-BearerCapability", "decoding", false)
				}
				_ = rawVal_gsmbearercapability
				if offset < 0 || offset >
					len(content) || n_gsmbearercapability < 0 || n_gsmbearercapability >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_gsmbearercapability, reconstructionErr_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_gsmbearercapability])
				if reconstructionErr_gsmbearercapability != nil {
					return qualifyBERError(reconstructionErr_gsmbearercapability, "gsm-BearerCapability", "decoding", false)
				}
				var dec_gsmbearercapability ExternalSignalInfo
				if unmErr := dec_gsmbearercapability.UnmarshalBER(reconstructed_gsmbearercapability, ber.ChildDecodeOptions(opts, "gsm-BearerCapability")...); unmErr != nil {
					return qualifyBERError(unmErr, "gsm-BearerCapability", "decoding", false)
				}
				v.GsmBearerCapability = &dec_gsmbearercapability
				if offset < 0 || offset >
					len(content) || n_gsmbearercapability < 0 || n_gsmbearercapability >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gsmbearercapability
			}
		}
	}
	// Decode networkSignalInfo
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "networkSignalInfo", content[offset:])
				decodedTag_networksignalinfo, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "networkSignalInfo", "decoding", false)
				}
				if decodedTag_networksignalinfo.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_networksignalinfo), "networkSignalInfo", "decoding", false)
				}
				if decodedTag_networksignalinfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo), "networkSignalInfo", "decoding", false)
				}
				_ = rawVal_networksignalinfo
				if offset < 0 || offset >
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_networksignalinfo, reconstructionErr_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_networksignalinfo])
				if reconstructionErr_networksignalinfo != nil {
					return qualifyBERError(reconstructionErr_networksignalinfo, "networkSignalInfo", "decoding", false)
				}
				var dec_networksignalinfo ExternalSignalInfo
				if unmErr := dec_networksignalinfo.UnmarshalBER(reconstructed_networksignalinfo, ber.ChildDecodeOptions(opts, "networkSignalInfo")...); unmErr != nil {
					return qualifyBERError(unmErr, "networkSignalInfo", "decoding", false)
				}
				v.NetworkSignalInfo = &dec_networksignalinfo
				if offset < 0 || offset >
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_networksignalinfo
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ProvideRoamingNumberArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ProvideRoamingNumberArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s1e3274_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

const (
	s1e3274_0 = "MAP-CH-DataTypes.CUG-CheckInfo"
	s1e3274_1 = "MAP-CH-DataTypes.SendRoutingInfoArg"
	s1e3274_2 = "MAP-CH-DataTypes.SendRoutingInfoRes"
	s1e3274_3 = "MAP-CH-DataTypes.RoutingInfo"
	s1e3274_4 = "MAP-CH-DataTypes.ProvideRoamingNumberArg"
)
