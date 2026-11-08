// Code generated from ASN.1 module "MAP-SS-DataTypes". DO NOT EDIT.

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

	// MaxNumOfCUG is the integer constant for maxNumOfCUG.
	MaxNumOfCUG int64 = 10

	// MaxUSSDStringLength is the integer constant for maxUSSD-StringLength.
	MaxUSSDStringLength int64 = 160

	// MaxNumOfSS is the integer constant for maxNumOfSS.
	MaxNumOfSS int64 = 30
)

// RegisterSSArg represents the ASN.1 type RegisterSS-Arg (SEQUENCE).
type RegisterSSArg struct {
	SsCode                SSCode                `asn1:""`
	BasicService          *BasicServiceCode     `asn1:",optional" json:"BasicService,omitempty"`
	ForwardedToNumber     *AddressString        `asn1:"tag:4,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString `asn1:"tag:6,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	NoReplyConditionTime  *NoReplyConditionTime `asn1:"tag:5,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	ExtCount_             int64                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// NoReplyConditionTime represents the ASN.1 type NoReplyConditionTime (INTEGER).
type NoReplyConditionTime = int64

// SSInfo choice constants.
const (
	SSInfoChoiceForwardingInfo  = 1
	SSInfoChoiceCallBarringInfo = 2
	SSInfoChoiceCugInfo         = 3
	SSInfoChoiceSsData          = 4
)

// SSInfo represents the ASN.1 CHOICE type SS-Info.
type SSInfo struct {
	Choice          int
	berReplayNode_  *ber.ReplayNode  `json:"-"`
	ForwardingInfo  *ForwardingInfo  `json:"ForwardingInfo,omitempty"`
	CallBarringInfo *CallBarringInfo `json:"CallBarringInfo,omitempty"`
	CugInfo         *CUGInfo         `json:"CugInfo,omitempty"`
	SsData          *SSData          `json:"SsData,omitempty"`
}

// NewSSInfoForwardingInfo creates a SSInfo with the forwardingInfo alternative.
func NewSSInfoForwardingInfo(v ForwardingInfo) SSInfo {
	return SSInfo{
		Choice:         SSInfoChoiceForwardingInfo,
		ForwardingInfo: &v,
	}
}

// NewSSInfoCallBarringInfo creates a SSInfo with the callBarringInfo alternative.
func NewSSInfoCallBarringInfo(v CallBarringInfo) SSInfo {
	return SSInfo{
		Choice:          SSInfoChoiceCallBarringInfo,
		CallBarringInfo: &v,
	}
}

// NewSSInfoCugInfo creates a SSInfo with the cug-Info alternative.
func NewSSInfoCugInfo(v CUGInfo) SSInfo {
	return SSInfo{
		Choice:  SSInfoChoiceCugInfo,
		CugInfo: &v,
	}
}

// NewSSInfoSsData creates a SSInfo with the ss-Data alternative.
func NewSSInfoSsData(v SSData) SSInfo {
	return SSInfo{
		Choice: SSInfoChoiceSsData,
		SsData: &v,
	}
}

// ForwardingInfo represents the ASN.1 type ForwardingInfo (SEQUENCE).
type ForwardingInfo struct {
	SsCode                         *SSCode                `asn1:",optional" json:"SsCode,omitempty"`
	ForwardingFeatureList          *ForwardingFeatureList `asn1:""`
	berForwardingFeatureListIndef_ bool                   `asn1:"-" json:"-"`
	ExtCount_                      int64                  `asn1:"-" json:"-"`
	ExtPresent_                    []bool                 `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ForwardingFeatureList represents the ASN.1 type ForwardingFeatureList (SEQUENCE_OF).
type ForwardingFeatureList struct {
	Values         []ForwardingFeature `json:"Values"`
	berReplayNode_ *ber.ReplayNode     `json:"-"`
}

// ForwardingFeature represents the ASN.1 type ForwardingFeature (SEQUENCE).
type ForwardingFeature struct {
	BasicService          *BasicServiceCode     `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus              *SSStatus             `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ForwardedToNumber     *ISDNAddressString    `asn1:"tag:5,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString `asn1:"tag:8,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	ForwardingOptions     *ForwardingOptions    `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	NoReplyConditionTime  *NoReplyConditionTime `asn1:"tag:7,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	ExtCount_             int64                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSStatus represents the ASN.1 type SS-Status (OCTET_STRING).
type SSStatus = []byte

// ForwardingOptions represents the ASN.1 type ForwardingOptions (OCTET_STRING).
type ForwardingOptions = []byte

// CallBarringInfo represents the ASN.1 type CallBarringInfo (SEQUENCE).
type CallBarringInfo struct {
	SsCode                          *SSCode                 `asn1:",optional" json:"SsCode,omitempty"`
	CallBarringFeatureList          *CallBarringFeatureList `asn1:""`
	berCallBarringFeatureListIndef_ bool                    `asn1:"-" json:"-"`
	ExtCount_                       int64                   `asn1:"-" json:"-"`
	ExtPresent_                     []bool                  `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CallBarringFeatureList represents the ASN.1 type CallBarringFeatureList (SEQUENCE_OF).
type CallBarringFeatureList struct {
	Values         []CallBarringFeature `json:"Values"`
	berReplayNode_ *ber.ReplayNode      `json:"-"`
}

// CallBarringFeature represents the ASN.1 type CallBarringFeature (SEQUENCE).
type CallBarringFeature struct {
	BasicService *BasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSStatus         `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64             `asn1:"-" json:"-"`
	ExtPresent_  []bool            `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CUGInfo represents the ASN.1 type CUG-Info (SEQUENCE).
type CUGInfo struct {
	CugSubscriptionList          *CUGSubscriptionList `asn1:""`
	berCugSubscriptionListIndef_ bool                 `asn1:"-" json:"-"`
	CugFeatureList               *CUGFeatureList      `asn1:",optional" json:"CugFeatureList,omitempty"`
	berCugFeatureListIndef_      bool                 `asn1:"-" json:"-"`
	ExtCount_                    int64                `asn1:"-" json:"-"`
	ExtPresent_                  []bool               `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CUGSubscriptionList represents the ASN.1 type CUG-SubscriptionList (SEQUENCE_OF).
type CUGSubscriptionList struct {
	Values         []CUGSubscription `json:"Values"`
	berReplayNode_ *ber.ReplayNode   `json:"-"`
}

// CUGSubscription represents the ASN.1 type CUG-Subscription (SEQUENCE).
type CUGSubscription struct {
	CugIndex                       CUGIndex               `asn1:""`
	CugInterlock                   CUGInterlock           `asn1:""`
	IntraCUGOptions                IntraCUGOptions        `asn1:""`
	BasicServiceGroupList          *BasicServiceGroupList `asn1:",optional" json:"BasicServiceGroupList,omitempty"`
	berBasicServiceGroupListIndef_ bool                   `asn1:"-" json:"-"`
	ExtCount_                      int64                  `asn1:"-" json:"-"`
	ExtPresent_                    []bool                 `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CUGIndex represents the ASN.1 type CUG-Index (INTEGER).
type CUGIndex = int64

// CUGInterlock represents the ASN.1 type CUG-Interlock (OCTET_STRING).
type CUGInterlock = []byte

// IntraCUGOptions represents the ASN.1 ENUMERATED type IntraCUG-Options.
type IntraCUGOptions int64

const (
	IntraCUGOptionsNoCUGRestrictions IntraCUGOptions = 0
	IntraCUGOptionsCugICCallBarred   IntraCUGOptions = 1
	IntraCUGOptionsCugOGCallBarred   IntraCUGOptions = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v IntraCUGOptions) String() string {
	switch v {
	case IntraCUGOptionsNoCUGRestrictions:
		return "noCUG-Restrictions"
	case IntraCUGOptionsCugICCallBarred:
		return "cugIC-CallBarred"
	case IntraCUGOptionsCugOGCallBarred:
		return "cugOG-CallBarred"
	default:
		return "unknown"
	}
}

// CUGFeatureList represents the ASN.1 type CUG-FeatureList (SEQUENCE_OF).
type CUGFeatureList struct {
	Values         []CUGFeature    `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// CUGFeature represents the ASN.1 type CUG-Feature (SEQUENCE).
type CUGFeature struct {
	BasicService             *BasicServiceCode    `asn1:",optional" json:"BasicService,omitempty"`
	PreferentialCUGIndicator *CUGIndex            `asn1:",optional" json:"PreferentialCUGIndicator,omitempty"`
	InterCUGRestrictions     InterCUGRestrictions `asn1:""`
	ExtCount_                int64                `asn1:"-" json:"-"`
	ExtPresent_              []bool               `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// InterCUGRestrictions represents the ASN.1 type InterCUG-Restrictions (OCTET_STRING).
type InterCUGRestrictions = []byte

// SSData represents the ASN.1 type SS-Data (SEQUENCE).
type SSData struct {
	SsCode                         *SSCode                `asn1:",optional" json:"SsCode,omitempty"`
	SsStatus                       *SSStatus              `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	SsSubscriptionOption           *SSSubscriptionOption  `asn1:",optional" json:"SsSubscriptionOption,omitempty"`
	BasicServiceGroupList          *BasicServiceGroupList `asn1:",optional" json:"BasicServiceGroupList,omitempty"`
	berBasicServiceGroupListIndef_ bool                   `asn1:"-" json:"-"`
	ExtCount_                      int64                  `asn1:"-" json:"-"`
	ExtPresent_                    []bool                 `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSSubscriptionOption choice constants.
const (
	SSSubscriptionOptionChoiceCliRestrictionOption = 1
	SSSubscriptionOptionChoiceOverrideCategory     = 2
)

// SSSubscriptionOption represents the ASN.1 CHOICE type SS-SubscriptionOption.
type SSSubscriptionOption struct {
	Choice               int
	berReplayNode_       *ber.ReplayNode       `json:"-"`
	CliRestrictionOption *CliRestrictionOption `json:"CliRestrictionOption,omitempty"`
	OverrideCategory     *OverrideCategory     `json:"OverrideCategory,omitempty"`
}

// NewSSSubscriptionOptionCliRestrictionOption creates a SSSubscriptionOption with the cliRestrictionOption alternative.
func NewSSSubscriptionOptionCliRestrictionOption(v CliRestrictionOption) SSSubscriptionOption {
	return SSSubscriptionOption{
		Choice:               SSSubscriptionOptionChoiceCliRestrictionOption,
		CliRestrictionOption: &v,
	}
}

// NewSSSubscriptionOptionOverrideCategory creates a SSSubscriptionOption with the overrideCategory alternative.
func NewSSSubscriptionOptionOverrideCategory(v OverrideCategory) SSSubscriptionOption {
	return SSSubscriptionOption{
		Choice:           SSSubscriptionOptionChoiceOverrideCategory,
		OverrideCategory: &v,
	}
}

// CliRestrictionOption represents the ASN.1 ENUMERATED type CliRestrictionOption.
type CliRestrictionOption int64

const (
	CliRestrictionOptionPermanent                  CliRestrictionOption = 0
	CliRestrictionOptionTemporaryDefaultRestricted CliRestrictionOption = 1
	CliRestrictionOptionTemporaryDefaultAllowed    CliRestrictionOption = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CliRestrictionOption) String() string {
	switch v {
	case CliRestrictionOptionPermanent:
		return "permanent"
	case CliRestrictionOptionTemporaryDefaultRestricted:
		return "temporaryDefaultRestricted"
	case CliRestrictionOptionTemporaryDefaultAllowed:
		return "temporaryDefaultAllowed"
	default:
		return "unknown"
	}
}

// OverrideCategory represents the ASN.1 ENUMERATED type OverrideCategory.
type OverrideCategory int64

const (
	OverrideCategoryOverrideEnabled  OverrideCategory = 0
	OverrideCategoryOverrideDisabled OverrideCategory = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v OverrideCategory) String() string {
	switch v {
	case OverrideCategoryOverrideEnabled:
		return "overrideEnabled"
	case OverrideCategoryOverrideDisabled:
		return "overrideDisabled"
	default:
		return "unknown"
	}
}

// SSForBSCode represents the ASN.1 type SS-ForBS-Code (SEQUENCE).
type SSForBSCode struct {
	SsCode       SSCode            `asn1:""`
	BasicService *BasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	ExtCount_    int64             `asn1:"-" json:"-"`
	ExtPresent_  []bool            `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CliRestrictionInfo represents the ASN.1 type Cli-RestrictionInfo (SEQUENCE).
type CliRestrictionInfo struct {
	SsStatus             SSStatus              `asn1:""`
	CliRestrictionOption *CliRestrictionOption `asn1:",optional" json:"CliRestrictionOption,omitempty"`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// InterrogateSSRes choice constants.
const (
	InterrogateSSResChoiceSsStatus              = 1
	InterrogateSSResChoiceForwardedToNumber     = 2
	InterrogateSSResChoiceBasicServiceGroupList = 3
	InterrogateSSResChoiceForwardingFeatureList = 4
	InterrogateSSResChoiceCliRestrictionInfo    = 5
)

// InterrogateSSRes represents the ASN.1 CHOICE type InterrogateSS-Res.
type InterrogateSSRes struct {
	Choice                int
	berReplayNode_        *ber.ReplayNode        `json:"-"`
	SsStatus              *SSStatus              `json:"SsStatus,omitempty"`
	ForwardedToNumber     *ISDNAddressString     `json:"ForwardedToNumber,omitempty"`
	BasicServiceGroupList *BasicServiceGroupList `json:"BasicServiceGroupList,omitempty"`
	ForwardingFeatureList *ForwardingFeatureList `json:"ForwardingFeatureList,omitempty"`
	CliRestrictionInfo    *CliRestrictionInfo    `json:"CliRestrictionInfo,omitempty"`
}

// NewInterrogateSSResSsStatus creates a InterrogateSSRes with the ss-Status alternative.
func NewInterrogateSSResSsStatus(v SSStatus) InterrogateSSRes {
	return InterrogateSSRes{
		Choice:   InterrogateSSResChoiceSsStatus,
		SsStatus: &v,
	}
}

// NewInterrogateSSResForwardedToNumber creates a InterrogateSSRes with the forwardedToNumber alternative.
func NewInterrogateSSResForwardedToNumber(v ISDNAddressString) InterrogateSSRes {
	return InterrogateSSRes{
		Choice:            InterrogateSSResChoiceForwardedToNumber,
		ForwardedToNumber: &v,
	}
}

// NewInterrogateSSResBasicServiceGroupList creates a InterrogateSSRes with the basicServiceGroupList alternative.
func NewInterrogateSSResBasicServiceGroupList(v *BasicServiceGroupList) InterrogateSSRes {
	return InterrogateSSRes{
		Choice:                InterrogateSSResChoiceBasicServiceGroupList,
		BasicServiceGroupList: v,
	}
}

// NewInterrogateSSResForwardingFeatureList creates a InterrogateSSRes with the forwardingFeatureList alternative.
func NewInterrogateSSResForwardingFeatureList(v *ForwardingFeatureList) InterrogateSSRes {
	return InterrogateSSRes{
		Choice:                InterrogateSSResChoiceForwardingFeatureList,
		ForwardingFeatureList: v,
	}
}

// NewInterrogateSSResCliRestrictionInfo creates a InterrogateSSRes with the cli-RestrictionInfo alternative.
func NewInterrogateSSResCliRestrictionInfo(v CliRestrictionInfo) InterrogateSSRes {
	return InterrogateSSRes{
		Choice:             InterrogateSSResChoiceCliRestrictionInfo,
		CliRestrictionInfo: &v,
	}
}

// SSUserData represents the ASN.1 type SS-UserData (IA5String).
type SSUserData = string

// USSDArg represents the ASN.1 type USSD-Arg (SEQUENCE).
type USSDArg struct {
	UssdDataCodingScheme USSDDataCodingScheme `asn1:""`
	UssdString           USSDString           `asn1:""`
	ExtCount_            int64                `asn1:"-" json:"-"`
	ExtPresent_          []bool               `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// USSDRes represents the ASN.1 type USSD-Res (SEQUENCE).
type USSDRes struct {
	UssdDataCodingScheme USSDDataCodingScheme `asn1:""`
	UssdString           USSDString           `asn1:""`
	ExtCount_            int64                `asn1:"-" json:"-"`
	ExtPresent_          []bool               `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// USSDDataCodingScheme represents the ASN.1 type USSD-DataCodingScheme (OCTET_STRING).
type USSDDataCodingScheme = []byte

// USSDString represents the ASN.1 type USSD-String (OCTET_STRING).
type USSDString = []byte

// Password represents the ASN.1 type Password (NumericString).
type Password = string

// GuidanceInfo represents the ASN.1 ENUMERATED type GuidanceInfo.
type GuidanceInfo int64

const (
	GuidanceInfoEnterPW             GuidanceInfo = 0
	GuidanceInfoEnterNewPW          GuidanceInfo = 1
	GuidanceInfoEnterNewPWAgain     GuidanceInfo = 2
	GuidanceInfoBadPWTryAgain       GuidanceInfo = 3
	GuidanceInfoBadPWFormatTryAgain GuidanceInfo = 4
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v GuidanceInfo) String() string {
	switch v {
	case GuidanceInfoEnterPW:
		return "enterPW"
	case GuidanceInfoEnterNewPW:
		return "enterNewPW"
	case GuidanceInfoEnterNewPWAgain:
		return "enterNewPW-Again"
	case GuidanceInfoBadPWTryAgain:
		return "badPW-TryAgain"
	case GuidanceInfoBadPWFormatTryAgain:
		return "badPW-FormatTryAgain"
	default:
		return "unknown"
	}
}

// BeginSubscriberActivityArg represents the ASN.1 type BeginSubscriberActivityArg (SEQUENCE).
type BeginSubscriberActivityArg struct {
	Imsi                    IMSI              `asn1:""`
	OriginatingEntityNumber ISDNAddressString `asn1:""`
	berReplayNode_          *ber.ReplayNode   `asn1:"-" json:"-"`
}

// SSList represents the ASN.1 type SS-List (SEQUENCE_OF).
type SSList struct {
	Values         []SSCode        `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// SSInfoList represents the ASN.1 type SS-InfoList (SEQUENCE_OF).
type SSInfoList struct {
	Values         []SSInfo        `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// ForwardingData represents the ASN.1 type ForwardingData (SEQUENCE).
type ForwardingData struct {
	ForwardedToNumber     *ISDNAddressString    `asn1:"tag:5,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString `asn1:"tag:4,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	ForwardingOptions     *ForwardingOptions    `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	ExtCount_             int64                 `asn1:"-" json:"-"`
	ExtPresent_           []bool                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes RegisterSSArg to BER format.
func (v *RegisterSSArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RegisterSSArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RegisterSSArg).MarshalBER, (*RegisterSSArg).marshalBER, 3)

}
func (v *RegisterSSArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
	}
	children = append(children, enc_sscode...)
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(ber.ChildEncodeOptions(opts, "basicService")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservice)
		children = append(children, enc_basicservice...)
	}
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", false)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", false)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", false)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", false)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := checkEncodedValue(opts, s7acebb_0, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		retagged_enc_noreplyconditiontime, tagErr_enc_noreplyconditiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_noreplyconditiontime)
		if tagErr_enc_noreplyconditiontime != nil {
			return nil, qualifyBERError(tagErr_enc_noreplyconditiontime, "noReplyConditionTime", "encoding", false)
		}
		enc_noreplyconditiontime = retagged_enc_noreplyconditiontime
		children = append(children, enc_noreplyconditiontime...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_0, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7acebb_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *RegisterSSArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes RegisterSSArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RegisterSSArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RegisterSSArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
	}
	children = append(children, enc_sscode...)
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", true)
		}
		children = append(children, enc_basicservice...)
	}
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", true)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", true)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", true)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", true)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := checkEncodedValue(nil, s7acebb_0, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		retagged_enc_noreplyconditiontime, tagErr_enc_noreplyconditiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_noreplyconditiontime)
		if tagErr_enc_noreplyconditiontime != nil {
			return nil, qualifyBERError(tagErr_enc_noreplyconditiontime, "noReplyConditionTime", "encoding", true)
		}
		enc_noreplyconditiontime = retagged_enc_noreplyconditiontime
		children = append(children, enc_noreplyconditiontime...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_0, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7acebb_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding RegisterSSArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *RegisterSSArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RegisterSSArg from BER/DER format.
func (destination *RegisterSSArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RegisterSSArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(RegisterSSArg)
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
			var probe RegisterSSArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_0, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RegisterSSArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RegisterSSArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding RegisterSSArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterSSArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field ss-Code", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
		val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Code", "decoding", false)
		}
		v.SsCode = SSCode(val_sscode)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				ber.MarkPreflightTarget(opts, "basicService", content[offset:])
				// Decode nested CHOICE (BasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return qualifyBERError(tlvErr_basicservice, "basicService", "decoding", false)
				}
				var dec_basicservice BasicServiceCode
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicService", "decoding", false)
				}
				v.BasicService = &dec_basicservice
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservice
			}
		}
	}
	// Decode forwardedToNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "forwardedToNumber", content[offset:])
				decodedTag_forwardedtonumber, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardedToNumber", "decoding", false)
				}
				if decodedTag_forwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_forwardedtonumber.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_forwardedtonumber), "forwardedToNumber", "decoding", false)
				}
				decVal_forwardedtonumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtonumber.Constructed, rawVal_forwardedtonumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToNumber", "decoding", false)
				}
				tmp_forwardedtonumber := AddressString(decVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				if offset < 0 || offset >
					len(content) || n_forwardedtonumber < 0 || n_forwardedtonumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtonumber
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode forwardedToSubaddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "forwardedToSubaddress", content[offset:])
				decodedTag_forwardedtosubaddress, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardedToSubaddress", "decoding", false)
				}
				if decodedTag_forwardedtosubaddress.Class != tag.ClassContextSpecific || decodedTag_forwardedtosubaddress.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_forwardedtosubaddress), "forwardedToSubaddress", "decoding", false)
				}
				decVal_forwardedtosubaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtosubaddress.Constructed, rawVal_forwardedtosubaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToSubaddress", "decoding", false)
				}
				tmp_forwardedtosubaddress := ISDNSubaddressString(decVal_forwardedtosubaddress)
				v.ForwardedToSubaddress = &tmp_forwardedtosubaddress
				if offset < 0 || offset >
					len(content) || n_forwardedtosubaddress < 0 || n_forwardedtosubaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtosubaddress
				if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_0, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode noReplyConditionTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "noReplyConditionTime", content[offset:])
				decodedTag_noreplyconditiontime, n_noreplyconditiontime, rawVal_noreplyconditiontime, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "noReplyConditionTime", "decoding", false)
				}
				if decodedTag_noreplyconditiontime.Class != tag.ClassContextSpecific || decodedTag_noreplyconditiontime.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_noreplyconditiontime), "noReplyConditionTime", "decoding", false)
				}
				if decodedTag_noreplyconditiontime.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_noreplyconditiontime), "noReplyConditionTime", "decoding", false)
				}
				decVal_noreplyconditiontime, intErr := ber.DecodeIntegerValue(rawVal_noreplyconditiontime)
				if intErr != nil {
					return qualifyBERError(intErr, "noReplyConditionTime", "decoding", false)
				}
				tmp_noreplyconditiontime := NoReplyConditionTime(decVal_noreplyconditiontime)
				v.NoReplyConditionTime = &tmp_noreplyconditiontime
				if offset < 0 || offset >
					len(content) || n_noreplyconditiontime < 0 || n_noreplyconditiontime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_noreplyconditiontime
				if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
					if constraintErr := checkDecodedValue(opts, s7acebb_0, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterSSArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "RegisterSSArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7acebb_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SSInfo to BER format.
func (v *SSInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSInfo).MarshalBER, (*SSInfo).marshalBER, 3)

}
func (v *SSInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SSInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SSInfoChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInfo: forwardingInfo is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.ForwardingInfo.MarshalBER(ber.ChildEncodeOptions(opts, "forwardingInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingInfo", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "forwardingInfo", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SSInfoChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInfo: callBarringInfo is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.CallBarringInfo.MarshalBER(ber.ChildEncodeOptions(opts, "callBarringInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "callBarringInfo", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "callBarringInfo", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SSInfoChoiceCugInfo:
		if v.CugInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInfo: cug-Info is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.CugInfo.MarshalBER(ber.ChildEncodeOptions(opts, "cug-Info")...)
		if err != nil {
			return nil, qualifyBERError(err, "cug-Info", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "cug-Info", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SSInfoChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("%w: choice SSInfo: ss-Data is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.SsData.MarshalBER(ber.ChildEncodeOptions(opts, "ss-Data")...)
		if err != nil {
			return nil, qualifyBERError(err, "ss-Data", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "ss-Data", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSInfo", v.Choice)
	}
}

// MarshalDER encodes SSInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSInfo receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SSInfoChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInfo: forwardingInfo is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.ForwardingInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "forwardingInfo", "encoding", true)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "forwardingInfo", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "forwardingInfo", "encoding", true)
		}
		return enc_der_0, nil
	case SSInfoChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInfo: callBarringInfo is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.CallBarringInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "callBarringInfo", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "callBarringInfo", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "callBarringInfo", "encoding", true)
		}
		return enc_der_1, nil
	case SSInfoChoiceCugInfo:
		if v.CugInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInfo: cug-Info is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.CugInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cug-Info", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "cug-Info", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "cug-Info", "encoding", true)
		}
		return enc_der_2, nil
	case SSInfoChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("%w: choice SSInfo: ss-Data is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.SsData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "ss-Data", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "ss-Data", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "ss-Data", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SSInfoChoiceForwardingInfo:
			return nil, qualifyBERError(err, "forwardingInfo", "encoding", true)
		case SSInfoChoiceCallBarringInfo:
			return nil, qualifyBERError(err, "callBarringInfo", "encoding", true)
		case SSInfoChoiceCugInfo:
			return nil, qualifyBERError(err, "cug-Info", "encoding", true)
		case SSInfoChoiceSsData:
			return nil, qualifyBERError(err, "ss-Data", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SSInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SSInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSInfo from BER/DER format.
func (destination *SSInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSInfo)
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
				opts, v, &v.berReplayNode_, (*SSInfo).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SSInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-SS-DataTypes.SS-Info", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SSInfo CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInfo", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSInfo.forwardingInfo", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSInfo.callBarringInfo", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSInfo.cug-Info", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSInfo.ss-Data", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = SSInfoChoiceForwardingInfo
		ber.MarkPreflightTarget(opts, "forwardingInfo", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "forwardingInfo", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ForwardingInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "forwardingInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "forwardingInfo", "decoding", false)
		}
		v.ForwardingInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = SSInfoChoiceCallBarringInfo
		ber.MarkPreflightTarget(opts, "callBarringInfo", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "callBarringInfo", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec CallBarringInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "callBarringInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "callBarringInfo", "decoding", false)
		}
		v.CallBarringInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = SSInfoChoiceCugInfo
		ber.MarkPreflightTarget(opts, "cug-Info", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "cug-Info", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec CUGInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "cug-Info")...); unmErr != nil {
			return qualifyBERError(unmErr, "cug-Info", "decoding", false)
		}
		v.CugInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = SSInfoChoiceSsData
		ber.MarkPreflightTarget(opts, "ss-Data", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "ss-Data", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec SSData
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "ss-Data")...); unmErr != nil {
			return qualifyBERError(unmErr, "ss-Data", "decoding", false)
		}
		v.SsData = &dec
	} else {
		return fmt.Errorf("%w: unknown tag %s for SSInfo CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes ForwardingInfo to BER format.
func (v *ForwardingInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ForwardingInfo).MarshalBER, (*ForwardingInfo).marshalBER, 3)

}
func (v *ForwardingInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
		}
		children = append(children, enc_sscode...)
	}
	if v.ForwardingFeatureList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "forwardingFeatureList", "encoding", false)
	}
	if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_forwardingfeaturelist, err := MarshalBERForwardingFeatureList(v.ForwardingFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "forwardingFeatureList"))...)
	if err != nil {
		return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_forwardingfeaturelist)
	children = append(children, enc_forwardingfeaturelist...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_1, children, i, &base_); err != nil {
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
func (v *ForwardingInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ForwardingInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ForwardingInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
		}
		children = append(children, enc_sscode...)
	}
	if v.ForwardingFeatureList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "forwardingFeatureList", "encoding", true)
	}
	if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_forwardingfeaturelist, err := MarshalDERForwardingFeatureList(v.ForwardingFeatureList)
	if err != nil {
		return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", true)
	}
	children = append(children, enc_forwardingfeaturelist...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_1, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ForwardingInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ForwardingInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ForwardingInfo from BER/DER format.
func (destination *ForwardingInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ForwardingInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(ForwardingInfo)

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
			var probe ForwardingInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_1, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ForwardingInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ForwardingInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ForwardingInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
				val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Code", "decoding", false)
				}
				tmp_sscode := SSCode(val_sscode)
				v.SsCode = &tmp_sscode
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode forwardingFeatureList
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field forwardingFeatureList", ber.ErrUnexpectedElement)
	}
	{
		v.berForwardingFeatureListIndef_ = false
		ber.MarkPreflightTarget(opts, "forwardingFeatureList", content[offset:])
		// Decode nested SEQUENCE_OF (ForwardingFeatureList)
		_, n_forwardingfeaturelist, _, tlvErr_forwardingfeaturelist := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_forwardingfeaturelist != nil {
			return qualifyBERError(tlvErr_forwardingfeaturelist, "forwardingFeatureList", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_forwardingfeaturelist < 0 || n_forwardingfeaturelist >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tlv_forwardingfeaturelist := content[offset : offset+n_forwardingfeaturelist]
		{
			_, tagSz_, _ := ber.DecodeTag(tlv_forwardingfeaturelist)
			if tagSz_ < len(tlv_forwardingfeaturelist) && tlv_forwardingfeaturelist[tagSz_] == 0x80 {
				v.berForwardingFeatureListIndef_ = true
			}
		}
		dec_forwardingfeaturelist, unmErr := UnmarshalBERForwardingFeatureList(tlv_forwardingfeaturelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "forwardingFeatureList"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "forwardingFeatureList", "decoding", false)
		}
		v.ForwardingFeatureList = dec_forwardingfeaturelist
		if offset < 0 || offset >
			len(content) || n_forwardingfeaturelist < 0 || n_forwardingfeaturelist >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_forwardingfeaturelist
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_1, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingInfo", Cause: extErr_}
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

// MarshalBERForwardingFeatureList encodes a ForwardingFeatureList list to BER.
func MarshalBERForwardingFeatureList(collection *ForwardingFeatureList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERForwardingFeatureList, marshalBERForwardingFeatureList, 3, UnmarshalBERForwardingFeatureList)

}
func marshalBERForwardingFeatureList(collection *ForwardingFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-SS-DataTypes.marshalBERForwardingFeatureList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ForwardingFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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

func appendBERLinearForwardingFeatureList(encoder *ber.LinearEncoder, collection *ForwardingFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERForwardingFeatureList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERForwardingFeatureList encodes a ForwardingFeatureList list to DER.
func MarshalDERForwardingFeatureList(collection *ForwardingFeatureList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, "MAP-SS-DataTypes.ForwardingFeatureList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ForwardingFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ForwardingFeatureList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearForwardingFeatureList(encoder *ber.LinearEncoder, collection *ForwardingFeatureList) ([]byte, error) {
	encoded, err := MarshalDERForwardingFeatureList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERForwardingFeatureList decodes a ForwardingFeatureList list from BER.
func UnmarshalBERForwardingFeatureList(data []byte, opts ...ber.DecodeOption) (returnValue *ForwardingFeatureList, returnErr error) {
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
			_, probeErr := UnmarshalBERForwardingFeatureList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-SS-DataTypes.ForwardingFeatureList", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding ForwardingFeatureList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ForwardingFeatureList", Cause: ber.ErrExtraData}
	}
	var result []ForwardingFeature
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem ForwardingFeature
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
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, "MAP-SS-DataTypes.ForwardingFeatureList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ForwardingFeatureList", "SIZE (1..13)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &ForwardingFeatureList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERForwardingFeatureList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes ForwardingFeature to BER format.
func (v *ForwardingFeature) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingFeature receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ForwardingFeature).MarshalBER, (*ForwardingFeature).marshalBER, 3)

}
func (v *ForwardingFeature) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(ber.ChildEncodeOptions(opts, "basicService")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservice)
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", false)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", false)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", false)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", false)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", false)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", false)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardingoptions, encodeErr_enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		if encodeErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardingoptions, "forwardingOptions", "encoding", false)
		}
		retagged_enc_forwardingoptions, tagErr_enc_forwardingoptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardingoptions)
		if tagErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(tagErr_enc_forwardingoptions, "forwardingOptions", "encoding", false)
		}
		enc_forwardingoptions = retagged_enc_forwardingoptions
		children = append(children, enc_forwardingoptions...)
	}
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := checkEncodedValue(opts, s7acebb_2, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		retagged_enc_noreplyconditiontime, tagErr_enc_noreplyconditiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_noreplyconditiontime)
		if tagErr_enc_noreplyconditiontime != nil {
			return nil, qualifyBERError(tagErr_enc_noreplyconditiontime, "noReplyConditionTime", "encoding", false)
		}
		enc_noreplyconditiontime = retagged_enc_noreplyconditiontime
		children = append(children, enc_noreplyconditiontime...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_2, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7acebb_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ForwardingFeature) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ForwardingFeature to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ForwardingFeature) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingFeature receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", true)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", true)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", true)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", true)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", true)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", true)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", true)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardingoptions, encodeErr_enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		if encodeErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardingoptions, "forwardingOptions", "encoding", true)
		}
		retagged_enc_forwardingoptions, tagErr_enc_forwardingoptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardingoptions)
		if tagErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(tagErr_enc_forwardingoptions, "forwardingOptions", "encoding", true)
		}
		enc_forwardingoptions = retagged_enc_forwardingoptions
		children = append(children, enc_forwardingoptions...)
	}
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := checkEncodedValue(nil, s7acebb_2, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		retagged_enc_noreplyconditiontime, tagErr_enc_noreplyconditiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_noreplyconditiontime)
		if tagErr_enc_noreplyconditiontime != nil {
			return nil, qualifyBERError(tagErr_enc_noreplyconditiontime, "noReplyConditionTime", "encoding", true)
		}
		enc_noreplyconditiontime = retagged_enc_noreplyconditiontime
		children = append(children, enc_noreplyconditiontime...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_2, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7acebb_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ForwardingFeature as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ForwardingFeature) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ForwardingFeature from BER/DER format.
func (destination *ForwardingFeature) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ForwardingFeature destination is nil", ber.ErrInvalidValue)
	}
	v := new(ForwardingFeature)

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
			var probe ForwardingFeature
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_2, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ForwardingFeature{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ForwardingFeature).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ForwardingFeature SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingFeature", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				ber.MarkPreflightTarget(opts, "basicService", content[offset:])
				// Decode nested CHOICE (BasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return qualifyBERError(tlvErr_basicservice, "basicService", "decoding", false)
				}
				var dec_basicservice BasicServiceCode
				if offset > len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicService", "decoding", false)
				}
				v.BasicService = &dec_basicservice
				if offset > len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservice
			}
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "ss-Status", content[offset:])
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Status", "decoding", false)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_ssstatus), "ss-Status", "decoding", false)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "ss-Status", "decoding", false)
				}
				tmp_ssstatus := SSStatus(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode forwardedToNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "forwardedToNumber", content[offset:])
				decodedTag_forwardedtonumber, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardedToNumber", "decoding", false)
				}
				if decodedTag_forwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_forwardedtonumber.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_forwardedtonumber), "forwardedToNumber", "decoding", false)
				}
				decVal_forwardedtonumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtonumber.Constructed, rawVal_forwardedtonumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToNumber", "decoding", false)
				}
				tmp_forwardedtonumber := ISDNAddressString(decVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				if offset < 0 || offset >
					len(content) || n_forwardedtonumber < 0 || n_forwardedtonumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtonumber
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode forwardedToSubaddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				ber.MarkPreflightTarget(opts, "forwardedToSubaddress", content[offset:])
				decodedTag_forwardedtosubaddress, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardedToSubaddress", "decoding", false)
				}
				if decodedTag_forwardedtosubaddress.Class != tag.ClassContextSpecific || decodedTag_forwardedtosubaddress.Number != 8 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_forwardedtosubaddress), "forwardedToSubaddress", "decoding", false)
				}
				decVal_forwardedtosubaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtosubaddress.Constructed, rawVal_forwardedtosubaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToSubaddress", "decoding", false)
				}
				tmp_forwardedtosubaddress := ISDNSubaddressString(decVal_forwardedtosubaddress)
				v.ForwardedToSubaddress = &tmp_forwardedtosubaddress
				if offset < 0 || offset >
					len(content) || n_forwardedtosubaddress < 0 || n_forwardedtosubaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtosubaddress
				if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode forwardingOptions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "forwardingOptions", content[offset:])
				decodedTag_forwardingoptions, n_forwardingoptions, rawVal_forwardingoptions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardingOptions", "decoding", false)
				}
				if decodedTag_forwardingoptions.Class != tag.ClassContextSpecific || decodedTag_forwardingoptions.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_forwardingoptions), "forwardingOptions", "decoding", false)
				}
				decVal_forwardingoptions, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardingoptions.Constructed, rawVal_forwardingoptions, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardingOptions", "decoding", false)
				}
				tmp_forwardingoptions := ForwardingOptions(decVal_forwardingoptions)
				v.ForwardingOptions = &tmp_forwardingoptions
				if offset < 0 || offset >
					len(content) || n_forwardingoptions < 0 || n_forwardingoptions >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardingoptions
				if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_2, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode noReplyConditionTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "noReplyConditionTime", content[offset:])
				decodedTag_noreplyconditiontime, n_noreplyconditiontime, rawVal_noreplyconditiontime, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "noReplyConditionTime", "decoding", false)
				}
				if decodedTag_noreplyconditiontime.Class != tag.ClassContextSpecific || decodedTag_noreplyconditiontime.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_noreplyconditiontime), "noReplyConditionTime", "decoding", false)
				}
				if decodedTag_noreplyconditiontime.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_noreplyconditiontime), "noReplyConditionTime", "decoding", false)
				}
				decVal_noreplyconditiontime, intErr := ber.DecodeIntegerValue(rawVal_noreplyconditiontime)
				if intErr != nil {
					return qualifyBERError(intErr, "noReplyConditionTime", "decoding", false)
				}
				tmp_noreplyconditiontime := NoReplyConditionTime(decVal_noreplyconditiontime)
				v.NoReplyConditionTime = &tmp_noreplyconditiontime
				if offset < 0 || offset >
					len(content) || n_noreplyconditiontime < 0 || n_noreplyconditiontime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_noreplyconditiontime
				if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
					if constraintErr := checkDecodedValue(opts, s7acebb_2, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingFeature", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ForwardingFeature", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7acebb_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes CallBarringInfo to BER format.
func (v *CallBarringInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CallBarringInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CallBarringInfo).MarshalBER, (*CallBarringInfo).marshalBER, 3)

}
func (v *CallBarringInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
		}
		children = append(children, enc_sscode...)
	}
	if v.CallBarringFeatureList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "callBarringFeatureList", "encoding", false)
	}
	if len((v.CallBarringFeatureList).Values) < 1 || len((v.CallBarringFeatureList).Values) > 13 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callbarringfeaturelist, err := MarshalBERCallBarringFeatureList(v.CallBarringFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "callBarringFeatureList"))...)
	if err != nil {
		return nil, qualifyBERError(err, "callBarringFeatureList", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_callbarringfeaturelist)
	children = append(children, enc_callbarringfeaturelist...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_3, children, i, &base_); err != nil {
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
func (v *CallBarringInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CallBarringInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CallBarringInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CallBarringInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
		}
		children = append(children, enc_sscode...)
	}
	if v.CallBarringFeatureList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "callBarringFeatureList", "encoding", true)
	}
	if len((v.CallBarringFeatureList).Values) < 1 || len((v.CallBarringFeatureList).Values) > 13 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callbarringfeaturelist, err := MarshalDERCallBarringFeatureList(v.CallBarringFeatureList)
	if err != nil {
		return nil, qualifyBERError(err, "callBarringFeatureList", "encoding", true)
	}
	children = append(children, enc_callbarringfeaturelist...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_3, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding CallBarringInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CallBarringInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CallBarringInfo from BER/DER format.
func (destination *CallBarringInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CallBarringInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(CallBarringInfo)

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
			var probe CallBarringInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_3, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CallBarringInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CallBarringInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CallBarringInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarringInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
				val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Code", "decoding", false)
				}
				tmp_sscode := SSCode(val_sscode)
				v.SsCode = &tmp_sscode
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode callBarringFeatureList
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field callBarringFeatureList", ber.ErrUnexpectedElement)
	}
	{
		v.berCallBarringFeatureListIndef_ = false
		ber.MarkPreflightTarget(opts, "callBarringFeatureList", content[offset:])
		// Decode nested SEQUENCE_OF (CallBarringFeatureList)
		_, n_callbarringfeaturelist, _, tlvErr_callbarringfeaturelist := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_callbarringfeaturelist != nil {
			return qualifyBERError(tlvErr_callbarringfeaturelist, "callBarringFeatureList", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_callbarringfeaturelist < 0 || n_callbarringfeaturelist >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tlv_callbarringfeaturelist := content[offset : offset+n_callbarringfeaturelist]
		{
			_, tagSz_, _ := ber.DecodeTag(tlv_callbarringfeaturelist)
			if tagSz_ < len(tlv_callbarringfeaturelist) && tlv_callbarringfeaturelist[tagSz_] == 0x80 {
				v.berCallBarringFeatureListIndef_ = true
			}
		}
		dec_callbarringfeaturelist, unmErr := UnmarshalBERCallBarringFeatureList(tlv_callbarringfeaturelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "callBarringFeatureList"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "callBarringFeatureList", "decoding", false)
		}
		v.CallBarringFeatureList = dec_callbarringfeaturelist
		if offset < 0 || offset >
			len(content) || n_callbarringfeaturelist < 0 || n_callbarringfeaturelist >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_callbarringfeaturelist
		if len((v.CallBarringFeatureList).Values) < 1 || len((v.CallBarringFeatureList).Values) > 13 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_3, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CallBarringInfo", Cause: extErr_}
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

// MarshalBERCallBarringFeatureList encodes a CallBarringFeatureList list to BER.
func MarshalBERCallBarringFeatureList(collection *CallBarringFeatureList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERCallBarringFeatureList, marshalBERCallBarringFeatureList, 3, UnmarshalBERCallBarringFeatureList)

}
func marshalBERCallBarringFeatureList(collection *CallBarringFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-SS-DataTypes.marshalBERCallBarringFeatureList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "CallBarringFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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

func appendBERLinearCallBarringFeatureList(encoder *ber.LinearEncoder, collection *CallBarringFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERCallBarringFeatureList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERCallBarringFeatureList encodes a CallBarringFeatureList list to DER.
func MarshalDERCallBarringFeatureList(collection *CallBarringFeatureList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, "MAP-SS-DataTypes.CallBarringFeatureList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "CallBarringFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CallBarringFeatureList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearCallBarringFeatureList(encoder *ber.LinearEncoder, collection *CallBarringFeatureList) ([]byte, error) {
	encoded, err := MarshalDERCallBarringFeatureList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERCallBarringFeatureList decodes a CallBarringFeatureList list from BER.
func UnmarshalBERCallBarringFeatureList(data []byte, opts ...ber.DecodeOption) (returnValue *CallBarringFeatureList, returnErr error) {
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
			_, probeErr := UnmarshalBERCallBarringFeatureList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-SS-DataTypes.CallBarringFeatureList", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding CallBarringFeatureList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CallBarringFeatureList", Cause: ber.ErrExtraData}
	}
	var result []CallBarringFeature
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem CallBarringFeature
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
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, "MAP-SS-DataTypes.CallBarringFeatureList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "CallBarringFeatureList", "SIZE (1..13)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &CallBarringFeatureList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERCallBarringFeatureList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes CallBarringFeature to BER format.
func (v *CallBarringFeature) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CallBarringFeature receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CallBarringFeature).MarshalBER, (*CallBarringFeature).marshalBER, 3)

}
func (v *CallBarringFeature) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(ber.ChildEncodeOptions(opts, "basicService")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservice)
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", false)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", false)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_4, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7acebb_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CallBarringFeature) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CallBarringFeature to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CallBarringFeature) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CallBarringFeature receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", true)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", true)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", true)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_4, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7acebb_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CallBarringFeature as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CallBarringFeature) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CallBarringFeature from BER/DER format.
func (destination *CallBarringFeature) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CallBarringFeature destination is nil", ber.ErrInvalidValue)
	}
	v := new(CallBarringFeature)

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
			var probe CallBarringFeature
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_4, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CallBarringFeature{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CallBarringFeature).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CallBarringFeature SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarringFeature", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				ber.MarkPreflightTarget(opts, "basicService", content[offset:])
				// Decode nested CHOICE (BasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return qualifyBERError(tlvErr_basicservice, "basicService", "decoding", false)
				}
				var dec_basicservice BasicServiceCode
				if offset > len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicService", "decoding", false)
				}
				v.BasicService = &dec_basicservice
				if offset > len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservice
			}
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "ss-Status", content[offset:])
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Status", "decoding", false)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_ssstatus), "ss-Status", "decoding", false)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "ss-Status", "decoding", false)
				}
				tmp_ssstatus := SSStatus(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_4, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CallBarringFeature", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CallBarringFeature", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7acebb_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes CUGInfo to BER format.
func (v *CUGInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CUGInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CUGInfo).MarshalBER, (*CUGInfo).marshalBER, 3)

}
func (v *CUGInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CugSubscriptionList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "cug-SubscriptionList", "encoding", false)
	}
	if len((v.CugSubscriptionList).Values) < 1 || len((v.CugSubscriptionList).Values) > 10 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-SubscriptionList", "SIZE (1..10)", len((v.CugSubscriptionList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cugsubscriptionlist, err := MarshalBERCUGSubscriptionList(v.CugSubscriptionList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "cug-SubscriptionList"))...)
	if err != nil {
		return nil, qualifyBERError(err, "cug-SubscriptionList", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_cugsubscriptionlist)
	children = append(children, enc_cugsubscriptionlist...)
	if v.CugFeatureList != nil {
		if len((v.CugFeatureList).Values) < 1 || len((v.CugFeatureList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-FeatureList", "SIZE (1..13)", len((v.CugFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cugfeaturelist, err := MarshalBERCUGFeatureList(v.CugFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "cug-FeatureList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "cug-FeatureList", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_cugfeaturelist)
		children = append(children, enc_cugfeaturelist...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_5, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7acebb_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CUGInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CUGInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CUGInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CUGInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CugSubscriptionList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "cug-SubscriptionList", "encoding", true)
	}
	if len((v.CugSubscriptionList).Values) < 1 || len((v.CugSubscriptionList).Values) > 10 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-SubscriptionList", "SIZE (1..10)", len((v.CugSubscriptionList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cugsubscriptionlist, err := MarshalDERCUGSubscriptionList(v.CugSubscriptionList)
	if err != nil {
		return nil, qualifyBERError(err, "cug-SubscriptionList", "encoding", true)
	}
	children = append(children, enc_cugsubscriptionlist...)
	if v.CugFeatureList != nil {
		if len((v.CugFeatureList).Values) < 1 || len((v.CugFeatureList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-FeatureList", "SIZE (1..13)", len((v.CugFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cugfeaturelist, err := MarshalDERCUGFeatureList(v.CugFeatureList)
		if err != nil {
			return nil, qualifyBERError(err, "cug-FeatureList", "encoding", true)
		}
		children = append(children, enc_cugfeaturelist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_5, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7acebb_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CUGInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CUGInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CUGInfo from BER/DER format.
func (destination *CUGInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CUGInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(CUGInfo)
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
			var probe CUGInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_5, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CUGInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CUGInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CUGInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cug-SubscriptionList
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cug-SubscriptionList", ber.ErrUnexpectedElement)
	}
	{
		v.berCugSubscriptionListIndef_ = false
		ber.MarkPreflightTarget(opts, "cug-SubscriptionList", content[offset:])
		// Decode nested SEQUENCE_OF (CUGSubscriptionList)
		_, n_cugsubscriptionlist, _, tlvErr_cugsubscriptionlist := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_cugsubscriptionlist != nil {
			return qualifyBERError(tlvErr_cugsubscriptionlist, "cug-SubscriptionList", "decoding", false)
		}
		if offset > len(content) || n_cugsubscriptionlist < 0 || n_cugsubscriptionlist >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tlv_cugsubscriptionlist := content[offset : offset+n_cugsubscriptionlist]
		{
			_, tagSz_, _ := ber.DecodeTag(tlv_cugsubscriptionlist)
			if tagSz_ < len(tlv_cugsubscriptionlist) && tlv_cugsubscriptionlist[tagSz_] == 0x80 {
				v.berCugSubscriptionListIndef_ = true
			}
		}
		dec_cugsubscriptionlist, unmErr := UnmarshalBERCUGSubscriptionList(tlv_cugsubscriptionlist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "cug-SubscriptionList"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "cug-SubscriptionList", "decoding", false)
		}
		v.CugSubscriptionList = dec_cugsubscriptionlist
		if offset > len(content) || n_cugsubscriptionlist < 0 || n_cugsubscriptionlist >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_cugsubscriptionlist
		if len((v.CugSubscriptionList).Values) < 1 || len((v.CugSubscriptionList).Values) > 10 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-SubscriptionList", "SIZE (1..10)", len((v.CugSubscriptionList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cug-FeatureList
	v.berCugFeatureListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "cug-FeatureList", content[offset:])
				// Decode nested SEQUENCE_OF (CUGFeatureList)
				_, n_cugfeaturelist, _, tlvErr_cugfeaturelist := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_cugfeaturelist != nil {
					return qualifyBERError(tlvErr_cugfeaturelist, "cug-FeatureList", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_cugfeaturelist < 0 || n_cugfeaturelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_cugfeaturelist := content[offset : offset+n_cugfeaturelist]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_cugfeaturelist)
					if tagSz_ < len(tlv_cugfeaturelist) && tlv_cugfeaturelist[tagSz_] == 0x80 {
						v.berCugFeatureListIndef_ = true
					}
				}
				dec_cugfeaturelist, unmErr := UnmarshalBERCUGFeatureList(tlv_cugfeaturelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "cug-FeatureList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "cug-FeatureList", "decoding", false)
				}
				v.CugFeatureList = dec_cugfeaturelist
				if offset < 0 || offset >
					len(content) || n_cugfeaturelist < 0 || n_cugfeaturelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugfeaturelist
				if len((v.CugFeatureList).Values) < 1 || len((v.CugFeatureList).Values) > 13 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_5, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-FeatureList", "SIZE (1..13)", len((v.CugFeatureList).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CUGInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CUGInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7acebb_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBERCUGSubscriptionList encodes a CUGSubscriptionList list to BER.
func MarshalBERCUGSubscriptionList(collection *CUGSubscriptionList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERCUGSubscriptionList, marshalBERCUGSubscriptionList, 3, UnmarshalBERCUGSubscriptionList)

}
func marshalBERCUGSubscriptionList(collection *CUGSubscriptionList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-SS-DataTypes.marshalBERCUGSubscriptionList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "CUG-SubscriptionList", "SIZE (1..10)", len(list)); constraintErr != nil {
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

func appendBERLinearCUGSubscriptionList(encoder *ber.LinearEncoder, collection *CUGSubscriptionList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERCUGSubscriptionList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERCUGSubscriptionList encodes a CUGSubscriptionList list to DER.
func MarshalDERCUGSubscriptionList(collection *CUGSubscriptionList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, "MAP-SS-DataTypes.CUG-SubscriptionList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "CUG-SubscriptionList", "SIZE (1..10)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CUGSubscriptionList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearCUGSubscriptionList(encoder *ber.LinearEncoder, collection *CUGSubscriptionList) ([]byte, error) {
	encoded, err := MarshalDERCUGSubscriptionList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERCUGSubscriptionList decodes a CUGSubscriptionList list from BER.
func UnmarshalBERCUGSubscriptionList(data []byte, opts ...ber.DecodeOption) (returnValue *CUGSubscriptionList, returnErr error) {
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
			_, probeErr := UnmarshalBERCUGSubscriptionList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-SS-DataTypes.CUG-SubscriptionList", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding CUGSubscriptionList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CUGSubscriptionList", Cause: ber.ErrExtraData}
	}
	var result []CUGSubscription
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem CUGSubscription
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
	if len(result) < 1 || len(result) > 10 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, "MAP-SS-DataTypes.CUG-SubscriptionList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "CUG-SubscriptionList", "SIZE (1..10)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &CUGSubscriptionList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERCUGSubscriptionList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes CUGSubscription to BER format.
func (v *CUGSubscription) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CUGSubscription receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CUGSubscription).MarshalBER, (*CUGSubscription).marshalBER, 3)

}
func (v *CUGSubscription) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if !(int64(v.CugIndex) >= 0 && int64(v.CugIndex) <= 32767) {
		if constraintErr := checkEncodedValue(opts, s7acebb_6, "51.4", "cug-Index", "(0..32767)", ber.ObserveInteger(int64(v.CugIndex))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cugindex := ber.EncodeInteger(int64(v.CugIndex))
	children = append(children, enc_cugindex...)
	if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-Interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(v.CugInterlock))
	if encodeErr_enc_cuginterlock != nil {
		return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", false)
	}
	children = append(children, enc_cuginterlock...)
	if int64(v.IntraCUGOptions) != 0 && int64(v.IntraCUGOptions) != 1 && int64(v.IntraCUGOptions) != 2 {
		if constraintErr := checkEncodedValue(opts, s7acebb_6, "20", "intraCUG-Options", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(v.IntraCUGOptions))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_intracugoptions := ber.EncodeEnumerated(int64(v.IntraCUGOptions))
	children = append(children, enc_intracugoptions...)
	if v.BasicServiceGroupList != nil {
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservicegrouplist, err := MarshalBERBasicServiceGroupList(v.BasicServiceGroupList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "basicServiceGroupList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservicegrouplist)
		children = append(children, enc_basicservicegrouplist...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_6, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7acebb_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CUGSubscription) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CUGSubscription to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CUGSubscription) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CUGSubscription receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if !(int64(v.CugIndex) >= 0 && int64(v.CugIndex) <= 32767) {
		if constraintErr := checkEncodedValue(nil, s7acebb_6, "51.4", "cug-Index", "(0..32767)", ber.ObserveInteger(int64(v.CugIndex))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cugindex := ber.EncodeInteger(int64(v.CugIndex))
	children = append(children, enc_cugindex...)
	if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-Interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(v.CugInterlock))
	if encodeErr_enc_cuginterlock != nil {
		return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", true)
	}
	children = append(children, enc_cuginterlock...)
	if int64(v.IntraCUGOptions) != 0 && int64(v.IntraCUGOptions) != 1 && int64(v.IntraCUGOptions) != 2 {
		if constraintErr := checkEncodedValue(nil, s7acebb_6, "20", "intraCUG-Options", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(v.IntraCUGOptions))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_intracugoptions := ber.EncodeEnumerated(int64(v.IntraCUGOptions))
	children = append(children, enc_intracugoptions...)
	if v.BasicServiceGroupList != nil {
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservicegrouplist, err := MarshalDERBasicServiceGroupList(v.BasicServiceGroupList)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", true)
		}
		children = append(children, enc_basicservicegrouplist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_6, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7acebb_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CUGSubscription as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CUGSubscription) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CUGSubscription from BER/DER format.
func (destination *CUGSubscription) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CUGSubscription destination is nil", ber.ErrInvalidValue)
	}
	v := new(CUGSubscription)

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
			var probe CUGSubscription
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_6, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CUGSubscription{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CUGSubscription).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CUGSubscription SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGSubscription", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cug-Index
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cug-Index", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cug-Index", content[offset:])
		val_cugindex, n, err := ber.DecodeInteger(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cug-Index", "decoding", false)
		}
		v.CugIndex = CUGIndex(val_cugindex)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.CugIndex) >= 0 && int64(v.CugIndex) <= 32767) {
			if constraintErr := checkDecodedValue(opts, s7acebb_6, "51.4", "cug-Index", "(0..32767)", ber.ObserveInteger(int64(v.CugIndex))); constraintErr != nil {
				return constraintErr
			}
		}
	}
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
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "cug-Interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode intraCUG-Options
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field intraCUG-Options", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "intraCUG-Options", content[offset:])
		val_intracugoptions, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "intraCUG-Options", "decoding", false)
		}
		v.IntraCUGOptions = IntraCUGOptions(val_intracugoptions)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.IntraCUGOptions) != 0 && int64(v.IntraCUGOptions) != 1 && int64(v.IntraCUGOptions) != 2 {
			if constraintErr := checkDecodedValue(opts, s7acebb_6, "20", "intraCUG-Options", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(v.IntraCUGOptions))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode basicServiceGroupList
	v.berBasicServiceGroupListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "basicServiceGroupList", content[offset:])
				// Decode nested SEQUENCE_OF (BasicServiceGroupList)
				_, n_basicservicegrouplist, _, tlvErr_basicservicegrouplist := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservicegrouplist != nil {
					return qualifyBERError(tlvErr_basicservicegrouplist, "basicServiceGroupList", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_basicservicegrouplist < 0 || n_basicservicegrouplist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_basicservicegrouplist := content[offset : offset+n_basicservicegrouplist]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_basicservicegrouplist)
					if tagSz_ < len(tlv_basicservicegrouplist) && tlv_basicservicegrouplist[tagSz_] == 0x80 {
						v.berBasicServiceGroupListIndef_ = true
					}
				}
				dec_basicservicegrouplist, unmErr := UnmarshalBERBasicServiceGroupList(tlv_basicservicegrouplist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "basicServiceGroupList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "basicServiceGroupList", "decoding", false)
				}
				v.BasicServiceGroupList = dec_basicservicegrouplist
				if offset < 0 || offset >
					len(content) || n_basicservicegrouplist < 0 || n_basicservicegrouplist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservicegrouplist
				if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_6, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CUGSubscription", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CUGSubscription", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7acebb_6, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBERCUGFeatureList encodes a CUGFeatureList list to BER.
func MarshalBERCUGFeatureList(collection *CUGFeatureList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERCUGFeatureList, marshalBERCUGFeatureList, 3, UnmarshalBERCUGFeatureList)

}
func marshalBERCUGFeatureList(collection *CUGFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-SS-DataTypes.marshalBERCUGFeatureList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "CUG-FeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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

func appendBERLinearCUGFeatureList(encoder *ber.LinearEncoder, collection *CUGFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERCUGFeatureList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERCUGFeatureList encodes a CUGFeatureList list to DER.
func MarshalDERCUGFeatureList(collection *CUGFeatureList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, "MAP-SS-DataTypes.CUG-FeatureList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "CUG-FeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CUGFeatureList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearCUGFeatureList(encoder *ber.LinearEncoder, collection *CUGFeatureList) ([]byte, error) {
	encoded, err := MarshalDERCUGFeatureList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERCUGFeatureList decodes a CUGFeatureList list from BER.
func UnmarshalBERCUGFeatureList(data []byte, opts ...ber.DecodeOption) (returnValue *CUGFeatureList, returnErr error) {
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
			_, probeErr := UnmarshalBERCUGFeatureList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-SS-DataTypes.CUG-FeatureList", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding CUGFeatureList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CUGFeatureList", Cause: ber.ErrExtraData}
	}
	var result []CUGFeature
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem CUGFeature
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
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, "MAP-SS-DataTypes.CUG-FeatureList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "CUG-FeatureList", "SIZE (1..13)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &CUGFeatureList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERCUGFeatureList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes CUGFeature to BER format.
func (v *CUGFeature) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CUGFeature receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CUGFeature).MarshalBER, (*CUGFeature).marshalBER, 3)

}
func (v *CUGFeature) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(ber.ChildEncodeOptions(opts, "basicService")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservice)
		children = append(children, enc_basicservice...)
	}
	if v.PreferentialCUGIndicator != nil {
		if !(int64(*v.PreferentialCUGIndicator) >= 0 && int64(*v.PreferentialCUGIndicator) <= 32767) {
			if constraintErr := checkEncodedValue(opts, s7acebb_7, "51.4", "preferentialCUG-Indicator", "(0..32767)", ber.ObserveInteger(int64(*v.PreferentialCUGIndicator))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_preferentialcugindicator := ber.EncodeInteger(int64(*v.PreferentialCUGIndicator))
		children = append(children, enc_preferentialcugindicator...)
	}
	if len(v.InterCUGRestrictions) < 1 || len(v.InterCUGRestrictions) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "interCUG-Restrictions", "SIZE (1)", len(v.InterCUGRestrictions)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_intercugrestrictions, encodeErr_enc_intercugrestrictions := ber.EncodeOctetString([]byte(v.InterCUGRestrictions))
	if encodeErr_enc_intercugrestrictions != nil {
		return nil, qualifyBERError(encodeErr_enc_intercugrestrictions, "interCUG-Restrictions", "encoding", false)
	}
	children = append(children, enc_intercugrestrictions...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_7, children, i, &base_); err != nil {
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
func (v *CUGFeature) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CUGFeature to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CUGFeature) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CUGFeature receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", true)
		}
		children = append(children, enc_basicservice...)
	}
	if v.PreferentialCUGIndicator != nil {
		if !(int64(*v.PreferentialCUGIndicator) >= 0 && int64(*v.PreferentialCUGIndicator) <= 32767) {
			if constraintErr := checkEncodedValue(nil, s7acebb_7, "51.4", "preferentialCUG-Indicator", "(0..32767)", ber.ObserveInteger(int64(*v.PreferentialCUGIndicator))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_preferentialcugindicator := ber.EncodeInteger(int64(*v.PreferentialCUGIndicator))
		children = append(children, enc_preferentialcugindicator...)
	}
	if len(v.InterCUGRestrictions) < 1 || len(v.InterCUGRestrictions) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "interCUG-Restrictions", "SIZE (1)", len(v.InterCUGRestrictions)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_intercugrestrictions, encodeErr_enc_intercugrestrictions := ber.EncodeOctetString([]byte(v.InterCUGRestrictions))
	if encodeErr_enc_intercugrestrictions != nil {
		return nil, qualifyBERError(encodeErr_enc_intercugrestrictions, "interCUG-Restrictions", "encoding", true)
	}
	children = append(children, enc_intercugrestrictions...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_7, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding CUGFeature as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CUGFeature) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CUGFeature from BER/DER format.
func (destination *CUGFeature) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CUGFeature destination is nil", ber.ErrInvalidValue)
	}
	v := new(CUGFeature)
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
			var probe CUGFeature
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_7, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CUGFeature{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CUGFeature).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CUGFeature SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGFeature", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				ber.MarkPreflightTarget(opts, "basicService", content[offset:])
				// Decode nested CHOICE (BasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return qualifyBERError(tlvErr_basicservice, "basicService", "decoding", false)
				}
				var dec_basicservice BasicServiceCode
				if offset > len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicService", "decoding", false)
				}
				v.BasicService = &dec_basicservice
				if offset > len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservice
			}
		}
	}
	// Decode preferentialCUG-Indicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "preferentialCUG-Indicator", content[offset:])
				val_preferentialcugindicator, n, err := ber.DecodeInteger(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "preferentialCUG-Indicator", "decoding", false)
				}
				tmp_preferentialcugindicator := CUGIndex(val_preferentialcugindicator)
				v.PreferentialCUGIndicator = &tmp_preferentialcugindicator
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if !(int64(*v.PreferentialCUGIndicator) >= 0 && int64(*v.PreferentialCUGIndicator) <= 32767) {
					if constraintErr := checkDecodedValue(opts, s7acebb_7, "51.4", "preferentialCUG-Indicator", "(0..32767)", ber.ObserveInteger(int64(*v.PreferentialCUGIndicator))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode interCUG-Restrictions
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field interCUG-Restrictions", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "interCUG-Restrictions", content[offset:])
		val_intercugrestrictions, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "interCUG-Restrictions", "decoding", false)
		}
		v.InterCUGRestrictions = InterCUGRestrictions(val_intercugrestrictions)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.InterCUGRestrictions) < 1 || len(v.InterCUGRestrictions) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_7, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "interCUG-Restrictions", "SIZE (1)", len(v.InterCUGRestrictions)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CUGFeature", Cause: extErr_}
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

// MarshalBER encodes SSData to BER format.
func (v *SSData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSData).MarshalBER, (*SSData).marshalBER, 3)

}
func (v *SSData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
		}
		children = append(children, enc_sscode...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", false)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", false)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	if v.SsSubscriptionOption != nil {
		enc_sssubscriptionoption, err := v.SsSubscriptionOption.MarshalBER(ber.ChildEncodeOptions(opts, "ss-SubscriptionOption")...)
		if err != nil {
			return nil, qualifyBERError(err, "ss-SubscriptionOption", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_sssubscriptionoption)
		children = append(children, enc_sssubscriptionoption...)
	}
	if v.BasicServiceGroupList != nil {
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservicegrouplist, err := MarshalBERBasicServiceGroupList(v.BasicServiceGroupList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "basicServiceGroupList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservicegrouplist)
		children = append(children, enc_basicservicegrouplist...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_8, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7acebb_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
		}
		children = append(children, enc_sscode...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", true)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", true)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	if v.SsSubscriptionOption != nil {
		enc_sssubscriptionoption, err := v.SsSubscriptionOption.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "ss-SubscriptionOption", "encoding", true)
		}
		children = append(children, enc_sssubscriptionoption...)
	}
	if v.BasicServiceGroupList != nil {
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservicegrouplist, err := MarshalDERBasicServiceGroupList(v.BasicServiceGroupList)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", true)
		}
		children = append(children, enc_basicservicegrouplist...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_8, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7acebb_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSData from BER/DER format.
func (destination *SSData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSData destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSData)
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
			var probe SSData
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_8, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSData SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
				val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Code", "decoding", false)
				}
				tmp_sscode := SSCode(val_sscode)
				v.SsCode = &tmp_sscode
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "ss-Status", content[offset:])
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Status", "decoding", false)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_ssstatus), "ss-Status", "decoding", false)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "ss-Status", "decoding", false)
				}
				tmp_ssstatus := SSStatus(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ss-SubscriptionOption
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				ber.MarkPreflightTarget(opts, "ss-SubscriptionOption", content[offset:])
				// Decode nested CHOICE (SSSubscriptionOption)
				_, n_sssubscriptionoption, _, tlvErr_sssubscriptionoption := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_sssubscriptionoption != nil {
					return qualifyBERError(tlvErr_sssubscriptionoption, "ss-SubscriptionOption", "decoding", false)
				}
				var dec_sssubscriptionoption SSSubscriptionOption
				if offset < 0 || offset >
					len(content) || n_sssubscriptionoption < 0 || n_sssubscriptionoption >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_sssubscriptionoption.UnmarshalBER(content[offset:offset+n_sssubscriptionoption], ber.ChildDecodeOptions(opts, "ss-SubscriptionOption")...); unmErr != nil {
					return qualifyBERError(unmErr, "ss-SubscriptionOption", "decoding", false)
				}
				v.SsSubscriptionOption = &dec_sssubscriptionoption
				if offset < 0 || offset >
					len(content) || n_sssubscriptionoption < 0 || n_sssubscriptionoption >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sssubscriptionoption
			}
		}
	}
	// Decode basicServiceGroupList
	v.berBasicServiceGroupListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "basicServiceGroupList", content[offset:])
				// Decode nested SEQUENCE_OF (BasicServiceGroupList)
				_, n_basicservicegrouplist, _, tlvErr_basicservicegrouplist := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservicegrouplist != nil {
					return qualifyBERError(tlvErr_basicservicegrouplist, "basicServiceGroupList", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_basicservicegrouplist < 0 ||
					n_basicservicegrouplist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_basicservicegrouplist := content[offset : offset+n_basicservicegrouplist]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_basicservicegrouplist)
					if tagSz_ < len(tlv_basicservicegrouplist) && tlv_basicservicegrouplist[tagSz_] == 0x80 {
						v.berBasicServiceGroupListIndef_ = true
					}
				}
				dec_basicservicegrouplist, unmErr := UnmarshalBERBasicServiceGroupList(tlv_basicservicegrouplist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "basicServiceGroupList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "basicServiceGroupList", "decoding", false)
				}
				v.BasicServiceGroupList = dec_basicservicegrouplist
				if offset < 0 || offset >
					len(content) || n_basicservicegrouplist < 0 ||
					n_basicservicegrouplist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservicegrouplist
				if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_8, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSData", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSData", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7acebb_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes SSSubscriptionOption to BER format.
func (v *SSSubscriptionOption) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSSubscriptionOption receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSSubscriptionOption).MarshalBER, (*SSSubscriptionOption).marshalBER, 3)

}
func (v *SSSubscriptionOption) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SSSubscriptionOption) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SSSubscriptionOptionChoiceCliRestrictionOption:
		if v.CliRestrictionOption == nil {
			return nil, fmt.Errorf("%w: choice SSSubscriptionOption: cliRestrictionOption is nil", ber.ErrInvalidValue)
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
			if constraintErr := checkEncodedValue(opts, s7acebb_9, "20", "cliRestrictionOption", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "cliRestrictionOption", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SSSubscriptionOptionChoiceOverrideCategory:
		if v.OverrideCategory == nil {
			return nil, fmt.Errorf("%w: choice SSSubscriptionOption: overrideCategory is nil", ber.ErrInvalidValue)
		}
		enc_1 := ber.EncodeEnumerated(int64(*v.OverrideCategory))
		if int64(*v.OverrideCategory) != 0 && int64(*v.OverrideCategory) != 1 {
			if constraintErr := checkEncodedValue(opts, s7acebb_9, "20", "overrideCategory", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.OverrideCategory))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "overrideCategory", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSSubscriptionOption", v.Choice)
	}
}

// MarshalDER encodes SSSubscriptionOption to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSSubscriptionOption) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSubscriptionOption receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SSSubscriptionOptionChoiceCliRestrictionOption:
			return nil, qualifyBERError(err, "cliRestrictionOption", "encoding", true)
		case SSSubscriptionOptionChoiceOverrideCategory:
			return nil, qualifyBERError(err, "overrideCategory", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SSSubscriptionOption as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SSSubscriptionOption) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSSubscriptionOption from BER/DER format.
func (destination *SSSubscriptionOption) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSSubscriptionOption destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSSubscriptionOption)

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
				opts, v, &v.berReplayNode_, (*SSSubscriptionOption).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SSSubscriptionOption
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_9, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSSubscriptionOption{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSSubscriptionOption CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSSubscriptionOption: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SSSubscriptionOption CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSubscriptionOption", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSSubscriptionOption.cliRestrictionOption", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSSubscriptionOption.overrideCategory", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOptionChoiceCliRestrictionOption
		ber.MarkPreflightTarget(opts, "cliRestrictionOption", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "cliRestrictionOption", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeEnumeratedValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "cliRestrictionOption", "decoding", false)
		}
		tmp := CliRestrictionOption(decVal)
		v.CliRestrictionOption = &tmp
		if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
			if constraintErr := checkDecodedValue(opts, s7acebb_9, "20", "cliRestrictionOption", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOptionChoiceOverrideCategory
		ber.MarkPreflightTarget(opts, "overrideCategory", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "overrideCategory", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeEnumeratedValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "overrideCategory", "decoding", false)
		}
		tmp := OverrideCategory(decVal)
		v.OverrideCategory = &tmp
		if int64(*v.OverrideCategory) != 0 && int64(*v.OverrideCategory) != 1 {
			if constraintErr := checkDecodedValue(opts, s7acebb_9, "20", "overrideCategory", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.OverrideCategory))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for SSSubscriptionOption CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes SSForBSCode to BER format.
func (v *SSForBSCode) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSForBSCode receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSForBSCode).MarshalBER, (*SSForBSCode).marshalBER, 3)

}
func (v *SSForBSCode) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_10, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
	}
	children = append(children, enc_sscode...)
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(ber.ChildEncodeOptions(opts, "basicService")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservice)
		children = append(children, enc_basicservice...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_10, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7acebb_10, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSForBSCode) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSForBSCode to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSForBSCode) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSForBSCode receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_10, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
	}
	children = append(children, enc_sscode...)
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", true)
		}
		children = append(children, enc_basicservice...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_10, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7acebb_10, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSForBSCode as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSForBSCode) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSForBSCode from BER/DER format.
func (destination *SSForBSCode) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSForBSCode destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSForBSCode)
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
			var probe SSForBSCode
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_10, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSForBSCode{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSForBSCode).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSForBSCode SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSForBSCode", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field ss-Code", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
		val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Code", "decoding", false)
		}
		v.SsCode = SSCode(val_sscode)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_10, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				ber.MarkPreflightTarget(opts, "basicService", content[offset:])
				// Decode nested CHOICE (BasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return qualifyBERError(tlvErr_basicservice, "basicService", "decoding", false)
				}
				var dec_basicservice BasicServiceCode
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicService", "decoding", false)
				}
				v.BasicService = &dec_basicservice
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservice
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSForBSCode", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSForBSCode", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7acebb_10, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes CliRestrictionInfo to BER format.
func (v *CliRestrictionInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CliRestrictionInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CliRestrictionInfo).MarshalBER, (*CliRestrictionInfo).marshalBER, 3)

}
func (v *CliRestrictionInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", false)
	}
	children = append(children, enc_ssstatus...)
	if v.CliRestrictionOption != nil {
		if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
			if constraintErr := checkEncodedValue(opts, s7acebb_11, "20", "cliRestrictionOption", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_clirestrictionoption := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		children = append(children, enc_clirestrictionoption...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_11, children, i, &base_); err != nil {
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7acebb_11, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CliRestrictionInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CliRestrictionInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CliRestrictionInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CliRestrictionInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", true)
	}
	children = append(children, enc_ssstatus...)
	if v.CliRestrictionOption != nil {
		if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
			if constraintErr := checkEncodedValue(nil, s7acebb_11, "20", "cliRestrictionOption", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_clirestrictionoption := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		children = append(children, enc_clirestrictionoption...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_11, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7acebb_11, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding CliRestrictionInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CliRestrictionInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CliRestrictionInfo from BER/DER format.
func (destination *CliRestrictionInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CliRestrictionInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(CliRestrictionInfo)

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
			var probe CliRestrictionInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_11, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CliRestrictionInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CliRestrictionInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CliRestrictionInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CliRestrictionInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Status
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field ss-Status", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "ss-Status", content[offset:])
		val_ssstatus, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Status", "decoding", false)
		}
		v.SsStatus = SSStatus(val_ssstatus)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_11, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cliRestrictionOption
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "cliRestrictionOption", content[offset:])
				val_clirestrictionoption, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cliRestrictionOption", "decoding", false)
				}
				tmp_clirestrictionoption := CliRestrictionOption(val_clirestrictionoption)
				v.CliRestrictionOption = &tmp_clirestrictionoption
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
					if constraintErr := checkDecodedValue(opts, s7acebb_11, "20", "cliRestrictionOption", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.CliRestrictionOption))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CliRestrictionInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "CliRestrictionInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7acebb_11, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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

// MarshalBER encodes InterrogateSSRes to BER format.
func (v *InterrogateSSRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: InterrogateSSRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*InterrogateSSRes).MarshalBER, (*InterrogateSSRes).marshalBER, 3)

}
func (v *InterrogateSSRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *InterrogateSSRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case InterrogateSSResChoiceSsStatus:
		if v.SsStatus == nil {
			return nil, fmt.Errorf("%w: choice InterrogateSSRes: ss-Status is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "ss-Status", "encoding", false)
		}
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "ss-Status", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case InterrogateSSResChoiceForwardedToNumber:
		if v.ForwardedToNumber == nil {
			return nil, fmt.Errorf("%w: choice InterrogateSSRes: forwardedToNumber is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "forwardedToNumber", "encoding", false)
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "forwardedToNumber", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case InterrogateSSResChoiceBasicServiceGroupList:
		enc_2, err := MarshalBERBasicServiceGroupList(v.BasicServiceGroupList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "basicServiceGroupList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", false)
		}
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "basicServiceGroupList", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case InterrogateSSResChoiceForwardingFeatureList:
		enc_3, err := MarshalBERForwardingFeatureList(v.ForwardingFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "forwardingFeatureList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", false)
		}
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "forwardingFeatureList", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	case InterrogateSSResChoiceCliRestrictionInfo:
		if v.CliRestrictionInfo == nil {
			return nil, fmt.Errorf("%w: choice InterrogateSSRes: cli-RestrictionInfo is nil", ber.ErrInvalidValue)
		}
		enc_4, err := v.CliRestrictionInfo.MarshalBER(ber.ChildEncodeOptions(opts, "cli-RestrictionInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "cli-RestrictionInfo", "encoding", false)
		}
		retagged_enc_4, tagErr_enc_4 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_4)
		if tagErr_enc_4 != nil {
			return nil, qualifyBERError(tagErr_enc_4, "cli-RestrictionInfo", "encoding", false)
		}
		enc_4 = retagged_enc_4
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for InterrogateSSRes", v.Choice)
	}
}

// MarshalDER encodes InterrogateSSRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *InterrogateSSRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InterrogateSSRes receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case InterrogateSSResChoiceBasicServiceGroupList:
		enc_der_2, err := MarshalDERBasicServiceGroupList(v.BasicServiceGroupList)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", true)
		}
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "basicServiceGroupList", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "basicServiceGroupList", "encoding", true)
		}
		return enc_der_2, nil
	case InterrogateSSResChoiceForwardingFeatureList:
		enc_der_3, err := MarshalDERForwardingFeatureList(v.ForwardingFeatureList)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", true)
		}
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "forwardingFeatureList", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "forwardingFeatureList", "encoding", true)
		}
		return enc_der_3, nil
	case InterrogateSSResChoiceCliRestrictionInfo:
		if v.CliRestrictionInfo == nil {
			return nil, fmt.Errorf("%w: choice InterrogateSSRes: cli-RestrictionInfo is nil", ber.ErrInvalidValue)
		}
		enc_der_4, err := v.CliRestrictionInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cli-RestrictionInfo", "encoding", true)
		}
		retagged_enc_der_4, tagErr_enc_der_4 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_4)
		if tagErr_enc_der_4 != nil {
			return nil, qualifyBERError(tagErr_enc_der_4, "cli-RestrictionInfo", "encoding", true)
		}
		enc_der_4 = retagged_enc_der_4
		if derErr := ber.ValidateDEREncodedElement(enc_der_4); derErr != nil {
			return nil, qualifyBERError(derErr, "cli-RestrictionInfo", "encoding", true)
		}
		return enc_der_4, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case InterrogateSSResChoiceSsStatus:
			return nil, qualifyBERError(err, "ss-Status", "encoding", true)
		case InterrogateSSResChoiceForwardedToNumber:
			return nil, qualifyBERError(err, "forwardedToNumber", "encoding", true)
		case InterrogateSSResChoiceBasicServiceGroupList:
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", true)
		case InterrogateSSResChoiceForwardingFeatureList:
			return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", true)
		case InterrogateSSResChoiceCliRestrictionInfo:
			return nil, qualifyBERError(err, "cli-RestrictionInfo", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding InterrogateSSRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *InterrogateSSRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes InterrogateSSRes from BER/DER format.
func (destination *InterrogateSSRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: InterrogateSSRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(InterrogateSSRes)

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
				opts, v, &v.berReplayNode_, (*InterrogateSSRes).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe InterrogateSSRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_12, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = InterrogateSSRes{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for InterrogateSSRes CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InterrogateSSRes: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding InterrogateSSRes CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InterrogateSSRes", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "InterrogateSSRes.basicServiceGroupList", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "InterrogateSSRes.forwardingFeatureList", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "InterrogateSSRes.cli-RestrictionInfo", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = InterrogateSSResChoiceSsStatus
		ber.MarkPreflightTarget(opts, "ss-Status", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "ss-Status", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ss-Status", "decoding", false)
		}
		tmp := SSStatus(decVal)
		v.SsStatus = &tmp
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = InterrogateSSResChoiceForwardedToNumber
		ber.MarkPreflightTarget(opts, "forwardedToNumber", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "forwardedToNumber", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "forwardedToNumber", "decoding", false)
		}
		tmp := ISDNAddressString(decVal)
		v.ForwardedToNumber = &tmp
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = InterrogateSSResChoiceBasicServiceGroupList
		ber.MarkPreflightTarget(opts, "basicServiceGroupList", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "basicServiceGroupList", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERBasicServiceGroupList(reconstructed, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "basicServiceGroupList"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "basicServiceGroupList", "decoding", false)
		}
		v.BasicServiceGroupList = dec
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = InterrogateSSResChoiceForwardingFeatureList
		ber.MarkPreflightTarget(opts, "forwardingFeatureList", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "forwardingFeatureList", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERForwardingFeatureList(reconstructed, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "forwardingFeatureList"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "forwardingFeatureList", "decoding", false)
		}
		v.ForwardingFeatureList = dec
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_12, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = InterrogateSSResChoiceCliRestrictionInfo
		ber.MarkPreflightTarget(opts, "cli-RestrictionInfo", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "cli-RestrictionInfo", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec CliRestrictionInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "cli-RestrictionInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "cli-RestrictionInfo", "decoding", false)
		}
		v.CliRestrictionInfo = &dec
	} else {
		return fmt.Errorf("%w: unknown tag %s for InterrogateSSRes CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBERSSUserData encodes a typed standalone SSUserData, preserving unchanged received BER.
func MarshalBERSSUserData(value *BERValue[SSUserData], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required SSUserData is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERSSUserData, marshalBERSSUserData, 2, UnmarshalBERSSUserData)

}
func marshalBERSSUserData(value *BERValue[SSUserData], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value SSUserData }{Value: value.Value}
	_ = v
	var children []byte
	if constraintErr := checkIA5Controls(string(v.Value), opts, "SS-UserData", "MAP-SS-DataTypes.marshalBERSSUserData"); constraintErr != nil {
		return nil, constraintErr
	}
	for _, character := range []byte(v.Value) {
		if !(character >= 0x0 && character <= 0x7f) {
			if constraintErr := checkEncodedValue(opts, "MAP-SS-DataTypes.marshalBERSSUserData", "41", "SS-UserData", "IA5String character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
				return nil, constraintErr
			}
			break
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 200 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-SS-DataTypes.marshalBERSSUserData", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SS-UserData", "SIZE (1..200)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, stringErr := ber.EncodeTLV(tag.Tag{Number: 22}, []byte(string(v.Value)))
	if stringErr != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SS-UserData", qualifyBERError(stringErr, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERSSUserData encodes a typed standalone SSUserData using DER.
func MarshalDERSSUserData(value *BERValue[SSUserData]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required SSUserData is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value SSUserData }{Value: value.Value}
	_ = v
	var children []byte
	if constraintErr := checkIA5Controls(string(v.Value), nil, "SS-UserData", s7acebb_13); constraintErr != nil {
		return nil, constraintErr
	}
	for _, character := range []byte(v.Value) {
		if !(character >= 0x0 && character <= 0x7f) {
			if constraintErr := checkEncodedValue(nil, s7acebb_13, "41", "SS-UserData", "IA5String character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
				return nil, constraintErr
			}
			break
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 200 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_13, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SS-UserData", "SIZE (1..200)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, stringErr := ber.EncodeTLV(tag.Tag{Number: 22}, []byte(string(v.Value)))
	if stringErr != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SS-UserData", qualifyBERError(stringErr, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERSSUserData decodes one complete typed standalone SSUserData from BER/DER.
func UnmarshalBERSSUserData(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[SSUserData], returnErr error) {
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
			_, probeErr := UnmarshalBERSSUserData(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_13, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value SSUserData }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "SS-UserData", content[offset:])
		val_value, n, err := ber.DecodeString(content[offset:], 22, opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding SS-UserData", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = val_value
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		for _, character := range []byte(v.Value) {
			if !(character >= 0x0 && character <= 0x7f) {
				if constraintErr := checkDecodedValue(opts, s7acebb_13, "41", "SS-UserData", "IA5String character repertoire (X.680 (02/2021) §41)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return constraintErr
				}
				break
			}
		}
		if len(v.Value) < 1 || len(v.Value) > 200 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_13, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SS-UserData", "SIZE (1..200)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[SSUserData]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSUserData); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes USSDArg to BER format.
func (v *USSDArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: USSDArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*USSDArg).MarshalBER, (*USSDArg).marshalBER, 3)

}
func (v *USSDArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_14, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_ussddatacodingscheme, "ussd-DataCodingScheme", "encoding", false)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_14, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussdstring, encodeErr_enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	if encodeErr_enc_ussdstring != nil {
		return nil, qualifyBERError(encodeErr_enc_ussdstring, "ussd-String", "encoding", false)
	}
	children = append(children, enc_ussdstring...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_14, children, i, &base_); err != nil {
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
func (v *USSDArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes USSDArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *USSDArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: USSDArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_14, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_ussddatacodingscheme, "ussd-DataCodingScheme", "encoding", true)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_14, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussdstring, encodeErr_enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	if encodeErr_enc_ussdstring != nil {
		return nil, qualifyBERError(encodeErr_enc_ussdstring, "ussd-String", "encoding", true)
	}
	children = append(children, enc_ussdstring...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_14, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding USSDArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *USSDArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes USSDArg from BER/DER format.
func (destination *USSDArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: USSDArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(USSDArg)
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
			var probe USSDArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_14, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = USSDArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*USSDArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding USSDArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "USSDArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ussd-DataCodingScheme
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field ussd-DataCodingScheme", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "ussd-DataCodingScheme", content[offset:])
		val_ussddatacodingscheme, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ussd-DataCodingScheme", "decoding", false)
		}
		v.UssdDataCodingScheme = USSDDataCodingScheme(val_ussddatacodingscheme)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_14, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field ussd-String", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "ussd-String", content[offset:])
		val_ussdstring, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ussd-String", "decoding", false)
		}
		v.UssdString = USSDString(val_ussdstring)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_14, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "USSDArg", Cause: extErr_}
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

// MarshalBER encodes USSDRes to BER format.
func (v *USSDRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: USSDRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*USSDRes).MarshalBER, (*USSDRes).marshalBER, 3)

}
func (v *USSDRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_15, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_ussddatacodingscheme, "ussd-DataCodingScheme", "encoding", false)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_15, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussdstring, encodeErr_enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	if encodeErr_enc_ussdstring != nil {
		return nil, qualifyBERError(encodeErr_enc_ussdstring, "ussd-String", "encoding", false)
	}
	children = append(children, enc_ussdstring...)
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_15, children, i, &base_); err != nil {
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
func (v *USSDRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes USSDRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *USSDRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: USSDRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_15, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_ussddatacodingscheme, "ussd-DataCodingScheme", "encoding", true)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_15, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussdstring, encodeErr_enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	if encodeErr_enc_ussdstring != nil {
		return nil, qualifyBERError(encodeErr_enc_ussdstring, "ussd-String", "encoding", true)
	}
	children = append(children, enc_ussdstring...)
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_15, children, i)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding USSDRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *USSDRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes USSDRes from BER/DER format.
func (destination *USSDRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: USSDRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(USSDRes)
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
			var probe USSDRes
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_15, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = USSDRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*USSDRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding USSDRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "USSDRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ussd-DataCodingScheme
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field ussd-DataCodingScheme", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "ussd-DataCodingScheme", content[offset:])
		val_ussddatacodingscheme, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ussd-DataCodingScheme", "decoding", false)
		}
		v.UssdDataCodingScheme = USSDDataCodingScheme(val_ussddatacodingscheme)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_15, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field ussd-String", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "ussd-String", content[offset:])
		val_ussdstring, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ussd-String", "decoding", false)
		}
		v.UssdString = USSDString(val_ussdstring)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_15, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "USSDRes", Cause: extErr_}
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

// MarshalBERPassword encodes a typed standalone Password, preserving unchanged received BER.
func MarshalBERPassword(value *BERValue[Password], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required Password is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERPassword, marshalBERPassword, 2, UnmarshalBERPassword)

}
func marshalBERPassword(value *BERValue[Password], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value Password }{Value: value.Value}
	_ = v
	var children []byte
	for _, character := range []byte(v.Value) {
		if !(((character >= ' ' && character <= ' ') || (character >= '0' && character <= '9')) && (character >= '0' && character <= '9')) {
			if constraintErr := checkEncodedValue(opts, "MAP-SS-DataTypes.marshalBERPassword", "51.7", "Password", "FROM permitted alphabet", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
				return nil, constraintErr
			}
			break
		}
	}
	if len(v.Value) < 4 || len(v.Value) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-SS-DataTypes.marshalBERPassword", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "Password", "SIZE (4)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, stringErr := ber.EncodeTLV(tag.Tag{Number: 18}, []byte(string(v.Value)))
	if stringErr != nil {
		return nil, fmt.Errorf("%s: %w", "encoding Password", qualifyBERError(stringErr, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERPassword encodes a typed standalone Password using DER.
func MarshalDERPassword(value *BERValue[Password]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required Password is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value Password }{Value: value.Value}
	_ = v
	var children []byte
	for _, character := range []byte(v.Value) {
		if !(((character >= ' ' && character <= ' ') || (character >= '0' && character <= '9')) && (character >= '0' && character <= '9')) {
			if constraintErr := checkEncodedValue(nil, s7acebb_16, "51.7", "Password", "FROM permitted alphabet", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
				return nil, constraintErr
			}
			break
		}
	}
	if len(v.Value) < 4 || len(v.Value) > 4 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "Password", "SIZE (4)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, stringErr := ber.EncodeTLV(tag.Tag{Number: 18}, []byte(string(v.Value)))
	if stringErr != nil {
		return nil, fmt.Errorf("%s: %w", "encoding Password", qualifyBERError(stringErr, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERPassword decodes one complete typed standalone Password from BER/DER.
func UnmarshalBERPassword(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[Password], returnErr error) {
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
			_, probeErr := UnmarshalBERPassword(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_16, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value Password }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "Password", content[offset:])
		val_value, n, err := ber.DecodeString(content[offset:], 18, opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding Password", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = val_value
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		for _, character := range []byte(v.Value) {
			if !(((character >= ' ' && character <= ' ') || (character >= '0' && character <= '9')) && (character >= '0' && character <= '9')) {
				if constraintErr := checkDecodedValue(opts, s7acebb_16, "51.7", "Password", "FROM permitted alphabet", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return constraintErr
				}
				break
			}
		}
		if len(v.Value) < 4 || len(v.Value) > 4 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_16, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "Password", "SIZE (4)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[Password]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERPassword); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes BeginSubscriberActivityArg to BER format.
func (v *BeginSubscriberActivityArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: BeginSubscriberActivityArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*BeginSubscriberActivityArg).MarshalBER, (*BeginSubscriberActivityArg).marshalBER, 3)

}
func (v *BeginSubscriberActivityArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "originatingEntityNumber", "SIZE (1..9)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_originatingentitynumber, encodeErr_enc_originatingentitynumber := ber.EncodeOctetString([]byte(v.OriginatingEntityNumber))
	if encodeErr_enc_originatingentitynumber != nil {
		return nil, qualifyBERError(encodeErr_enc_originatingentitynumber, "originatingEntityNumber", "encoding", false)
	}
	children = append(children, enc_originatingentitynumber...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *BeginSubscriberActivityArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes BeginSubscriberActivityArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *BeginSubscriberActivityArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BeginSubscriberActivityArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "originatingEntityNumber", "SIZE (1..9)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_originatingentitynumber, encodeErr_enc_originatingentitynumber := ber.EncodeOctetString([]byte(v.OriginatingEntityNumber))
	if encodeErr_enc_originatingentitynumber != nil {
		return nil, qualifyBERError(encodeErr_enc_originatingentitynumber, "originatingEntityNumber", "encoding", true)
	}
	children = append(children, enc_originatingentitynumber...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding BeginSubscriberActivityArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *BeginSubscriberActivityArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes BeginSubscriberActivityArg from BER/DER format.
func (destination *BeginSubscriberActivityArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: BeginSubscriberActivityArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(BeginSubscriberActivityArg)

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
			var probe BeginSubscriberActivityArg
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_17, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = BeginSubscriberActivityArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*BeginSubscriberActivityArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding BeginSubscriberActivityArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BeginSubscriberActivityArg", Cause: ber.ErrExtraData}
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
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode originatingEntityNumber
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field originatingEntityNumber", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "originatingEntityNumber", content[offset:])
		val_originatingentitynumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "originatingEntityNumber", "decoding", false)
		}
		v.OriginatingEntityNumber = ISDNAddressString(val_originatingentitynumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 9 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "originatingEntityNumber", "SIZE (1..9)", len(v.OriginatingEntityNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_17, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "BeginSubscriberActivityArg", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBERSSList encodes a SSList list to BER.
func MarshalBERSSList(collection *SSList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSList, marshalBERSSList, 3, UnmarshalBERSSList)

}
func marshalBERSSList(collection *SSList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-SS-DataTypes.marshalBERSSList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SS-List", "SIZE (1..30)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, "MAP-SS-DataTypes.marshalBERSSList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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

func appendBERLinearSSList(encoder *ber.LinearEncoder, collection *SSList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSList encodes a SSList list to DER.
func MarshalDERSSList(collection *SSList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, s7acebb_18, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SS-List", "SIZE (1..30)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_18, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSList(encoder *ber.LinearEncoder, collection *SSList) ([]byte, error) {
	encoded, err := MarshalDERSSList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSList decodes a SSList list from BER.
func UnmarshalBERSSList(data []byte, opts ...ber.DecodeOption) (returnValue *SSList, returnErr error) {
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
			_, probeErr := UnmarshalBERSSList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_18, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSList", Cause: ber.ErrExtraData}
	}
	var result []SSCode
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
			if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_18, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), fmt.Sprintf("element[%d]", len(result)), "SIZE (1)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, SSCode(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 30 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, s7acebb_18, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SS-List", "SIZE (1..30)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERSSInfoList encodes a SSInfoList list to BER.
func MarshalBERSSInfoList(collection *SSInfoList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSInfoList, marshalBERSSInfoList, 3, UnmarshalBERSSInfoList)

}
func marshalBERSSInfoList(collection *SSInfoList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(opts, "MAP-SS-DataTypes.marshalBERSSInfoList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SS-InfoList", "SIZE (1..30)", len(list)); constraintErr != nil {
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

func appendBERLinearSSInfoList(encoder *ber.LinearEncoder, collection *SSInfoList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSInfoList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSInfoList encodes a SSInfoList list to DER.
func MarshalDERSSInfoList(collection *SSInfoList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := ber.CheckEncodedCollectionLength(ber.EncodeRule(nil, "MAP-SS-DataTypes.SS-InfoList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SS-InfoList", "SIZE (1..30)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSInfoList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSInfoList(encoder *ber.LinearEncoder, collection *SSInfoList) ([]byte, error) {
	encoded, err := MarshalDERSSInfoList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSInfoList decodes a SSInfoList list from BER.
func UnmarshalBERSSInfoList(data []byte, opts ...ber.DecodeOption) (returnValue *SSInfoList, returnErr error) {
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
			_, probeErr := UnmarshalBERSSInfoList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-SS-DataTypes.SS-InfoList", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSInfoList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSInfoList", Cause: ber.ErrExtraData}
	}
	var result []SSInfo
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem SSInfo
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
	if len(result) < 1 || len(result) > 30 {
		if constraintErr := ber.CheckDecodedCollectionLength(ber.DecodeRule(opts, "MAP-SS-DataTypes.SS-InfoList", ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "SS-InfoList", "SIZE (1..30)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSInfoList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSInfoList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes ForwardingData to BER format.
func (v *ForwardingData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ForwardingData).MarshalBER, (*ForwardingData).marshalBER, 3)

}
func (v *ForwardingData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", false)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", false)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", false)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", false)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(opts, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardingoptions, encodeErr_enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		if encodeErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardingoptions, "forwardingOptions", "encoding", false)
		}
		retagged_enc_forwardingoptions, tagErr_enc_forwardingoptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardingoptions)
		if tagErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(tagErr_enc_forwardingoptions, "forwardingOptions", "encoding", false)
		}
		enc_forwardingoptions = retagged_enc_forwardingoptions
		children = append(children, enc_forwardingoptions...)
	}
	base_ := -1
	for i, ext := range v.ExtData_ {
		if err := checkOpaqueAddition(ext, opts, s7acebb_19, children, i, &base_); err != nil {
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
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7acebb_19, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ForwardingData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ForwardingData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ForwardingData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", true)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", true)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", true)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, qualifyBERError(tagErr_enc_forwardedtosubaddress, "forwardedToSubaddress", "encoding", true)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := ber.CheckEncodedLength(ber.EncodeRule(nil, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardingoptions, encodeErr_enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		if encodeErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(encodeErr_enc_forwardingoptions, "forwardingOptions", "encoding", true)
		}
		retagged_enc_forwardingoptions, tagErr_enc_forwardingoptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardingoptions)
		if tagErr_enc_forwardingoptions != nil {
			return nil, qualifyBERError(tagErr_enc_forwardingoptions, "forwardingOptions", "encoding", true)
		}
		enc_forwardingoptions = retagged_enc_forwardingoptions
		children = append(children, enc_forwardingoptions...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, invalidDERAddition(ext, s7acebb_19, children, i)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7acebb_19, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding ForwardingData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ForwardingData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ForwardingData from BER/DER format.
func (destination *ForwardingData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ForwardingData destination is nil", ber.ErrInvalidValue)
	}
	v := new(ForwardingData)

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
			var probe ForwardingData
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s7acebb_19, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ForwardingData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ForwardingData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ForwardingData SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode forwardedToNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "forwardedToNumber", content[offset:])
				decodedTag_forwardedtonumber, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardedToNumber", "decoding", false)
				}
				if decodedTag_forwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_forwardedtonumber.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_forwardedtonumber), "forwardedToNumber", "decoding", false)
				}
				decVal_forwardedtonumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtonumber.Constructed, rawVal_forwardedtonumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToNumber", "decoding", false)
				}
				tmp_forwardedtonumber := ISDNAddressString(decVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				if offset > len(content) || n_forwardedtonumber < 0 || n_forwardedtonumber > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtonumber
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode forwardedToSubaddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "forwardedToSubaddress", content[offset:])
				decodedTag_forwardedtosubaddress, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardedToSubaddress", "decoding", false)
				}
				if decodedTag_forwardedtosubaddress.Class != tag.ClassContextSpecific || decodedTag_forwardedtosubaddress.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_forwardedtosubaddress), "forwardedToSubaddress", "decoding", false)
				}
				decVal_forwardedtosubaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtosubaddress.Constructed, rawVal_forwardedtosubaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToSubaddress", "decoding", false)
				}
				tmp_forwardedtosubaddress := ISDNSubaddressString(decVal_forwardedtosubaddress)
				v.ForwardedToSubaddress = &tmp_forwardedtosubaddress
				if offset < 0 || offset >
					len(content) || n_forwardedtosubaddress < 0 || n_forwardedtosubaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtosubaddress
				if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode forwardingOptions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "forwardingOptions", content[offset:])
				decodedTag_forwardingoptions, n_forwardingoptions, rawVal_forwardingoptions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "forwardingOptions", "decoding", false)
				}
				if decodedTag_forwardingoptions.Class != tag.ClassContextSpecific || decodedTag_forwardingoptions.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_forwardingoptions), "forwardingOptions", "decoding", false)
				}
				decVal_forwardingoptions, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardingoptions.Constructed, rawVal_forwardingoptions, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardingOptions", "decoding", false)
				}
				tmp_forwardingoptions := ForwardingOptions(decVal_forwardingoptions)
				v.ForwardingOptions = &tmp_forwardingoptions
				if offset < 0 || offset >
					len(content) || n_forwardingoptions < 0 || n_forwardingoptions >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardingoptions
				if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
					if constraintErr := ber.CheckDecodedLength(ber.DecodeRule(opts, s7acebb_19, ber.RuleRef{Document: "CCITT X.208 / X.209", Edition: "11/1988", Clause: "X.208 §§17.10, 37.4.3–37.4.4; X.209 §11.2"}), "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingData", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "ForwardingData", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrUnexpectedElement, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7acebb_19, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
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
	s7acebb_0  = "MAP-SS-DataTypes.RegisterSS-Arg"
	s7acebb_1  = "MAP-SS-DataTypes.ForwardingInfo"
	s7acebb_2  = "MAP-SS-DataTypes.ForwardingFeature"
	s7acebb_3  = "MAP-SS-DataTypes.CallBarringInfo"
	s7acebb_4  = "MAP-SS-DataTypes.CallBarringFeature"
	s7acebb_5  = "MAP-SS-DataTypes.CUG-Info"
	s7acebb_6  = "MAP-SS-DataTypes.CUG-Subscription"
	s7acebb_7  = "MAP-SS-DataTypes.CUG-Feature"
	s7acebb_8  = "MAP-SS-DataTypes.SS-Data"
	s7acebb_9  = "MAP-SS-DataTypes.SS-SubscriptionOption"
	s7acebb_10 = "MAP-SS-DataTypes.SS-ForBS-Code"
	s7acebb_11 = "MAP-SS-DataTypes.Cli-RestrictionInfo"
	s7acebb_12 = "MAP-SS-DataTypes.InterrogateSS-Res"
	s7acebb_13 = "MAP-SS-DataTypes.SS-UserData"
	s7acebb_14 = "MAP-SS-DataTypes.USSD-Arg"
	s7acebb_15 = "MAP-SS-DataTypes.USSD-Res"
	s7acebb_16 = "MAP-SS-DataTypes.Password"
	s7acebb_17 = "MAP-SS-DataTypes.BeginSubscriberActivityArg"
	s7acebb_18 = "MAP-SS-DataTypes.SS-List"
	s7acebb_19 = "MAP-SS-DataTypes.ForwardingData"
)
