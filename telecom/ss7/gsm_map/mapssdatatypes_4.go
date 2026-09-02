// Code generated from ASN.1 module "MAP-SS-DataTypes". DO NOT EDIT.

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

const (

	// MaxNumOfCCBSRequests4 is the integer constant for MaxNumOfCCBSRequests4.
	MaxNumOfCCBSRequests4 int64 = 5

	// MaxUSSDStringLength4 is the integer constant for MaxUSSDStringLength4.
	MaxUSSDStringLength4 int64 = 160

	// MaxNumOfSS4 is the integer constant for MaxNumOfSS4.
	MaxNumOfSS4 int64 = 30

	// MaxNumOfBasicServiceGroups4 is the integer constant for MaxNumOfBasicServiceGroups4.
	MaxNumOfBasicServiceGroups4 int64 = 13

	// MaxEventSpecification4 is the integer constant for MaxEventSpecification4.
	MaxEventSpecification4 int64 = 2
)

// RegisterSSArg4 represents the ASN.1 type RegisterSS-Arg (SEQUENCE).
type RegisterSSArg4 struct {
	SsCode                SSCode4                `asn1:""`
	BasicService          *BasicServiceCode4     `asn1:",optional" json:"BasicService,omitempty"`
	ForwardedToNumber     *AddressString4        `asn1:"tag:4,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString4 `asn1:"tag:6,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	NoReplyConditionTime  *NoReplyConditionTime4 `asn1:"tag:5,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	DefaultPriority       *EMLPPPriority4        `asn1:"tag:7,context,implicit,optional" json:"DefaultPriority,omitempty"`
	NbrUser               *MCBearers4            `asn1:"tag:8,context,implicit,optional" json:"NbrUser,omitempty"`
	LongFTNSupported      *struct{}              `asn1:"tag:9,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
}

// NoReplyConditionTime4 represents the ASN.1 type NoReplyConditionTime (INTEGER).
type NoReplyConditionTime4 = int64

// SSInfo4 choice constants.
const (
	SSInfo4ChoiceForwardingInfo  = 1
	SSInfo4ChoiceCallBarringInfo = 2
	SSInfo4ChoiceSsData          = 3
)

// SSInfo4 represents the ASN.1 CHOICE type SS-Info.
type SSInfo4 struct {
	Choice          int
	ForwardingInfo  *ForwardingInfo4  `json:"ForwardingInfo,omitempty"`
	CallBarringInfo *CallBarringInfo4 `json:"CallBarringInfo,omitempty"`
	SsData          *SSData4          `json:"SsData,omitempty"`
}

// NewSSInfo4ForwardingInfo creates a SSInfo4 with the forwardingInfo alternative.
func NewSSInfo4ForwardingInfo(v ForwardingInfo4) SSInfo4 {
	return SSInfo4{
		Choice:         SSInfo4ChoiceForwardingInfo,
		ForwardingInfo: &v,
	}
}

// NewSSInfo4CallBarringInfo creates a SSInfo4 with the callBarringInfo alternative.
func NewSSInfo4CallBarringInfo(v CallBarringInfo4) SSInfo4 {
	return SSInfo4{
		Choice:          SSInfo4ChoiceCallBarringInfo,
		CallBarringInfo: &v,
	}
}

// NewSSInfo4SsData creates a SSInfo4 with the ss-Data alternative.
func NewSSInfo4SsData(v SSData4) SSInfo4 {
	return SSInfo4{
		Choice: SSInfo4ChoiceSsData,
		SsData: &v,
	}
}

// ForwardingInfo4 represents the ASN.1 type ForwardingInfo (SEQUENCE).
type ForwardingInfo4 struct {
	SsCode                      *SSCode4               `asn1:",optional" json:"SsCode,omitempty"`
	ForwardingFeatureList       ForwardingFeatureList4 `asn1:""`
	ForwardingFeatureListIndef_ bool                   `asn1:"-" json:"-"`
	ExtCount_                   int64                  `asn1:"-" json:"-"`
	ExtPresent_                 []bool                 `asn1:"-" json:"-"`
	ExtData_                    [][]byte               `asn1:"-" json:"-"`
}

// ForwardingFeatureList4 represents the ASN.1 type ForwardingFeatureList (SEQUENCE_OF).
type ForwardingFeatureList4 = []ForwardingFeature4

// ForwardingFeature4 represents the ASN.1 type ForwardingFeature (SEQUENCE).
type ForwardingFeature4 struct {
	BasicService          *BasicServiceCode4     `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus              *SSStatus4             `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ForwardedToNumber     *ISDNAddressString4    `asn1:"tag:5,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString4 `asn1:"tag:8,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	ForwardingOptions     *ForwardingOptions4    `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	NoReplyConditionTime  *NoReplyConditionTime4 `asn1:"tag:7,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	LongForwardedToNumber *FTNAddressString4     `asn1:"tag:9,context,implicit,optional" json:"LongForwardedToNumber,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
}

// SSStatus4 represents the ASN.1 type SS-Status (OCTET_STRING).
type SSStatus4 = []byte

// ForwardingOptions4 represents the ASN.1 type ForwardingOptions (OCTET_STRING).
type ForwardingOptions4 = []byte

// CallBarringInfo4 represents the ASN.1 type CallBarringInfo (SEQUENCE).
type CallBarringInfo4 struct {
	SsCode                       *SSCode4                `asn1:",optional" json:"SsCode,omitempty"`
	CallBarringFeatureList       CallBarringFeatureList4 `asn1:""`
	CallBarringFeatureListIndef_ bool                    `asn1:"-" json:"-"`
	ExtCount_                    int64                   `asn1:"-" json:"-"`
	ExtPresent_                  []bool                  `asn1:"-" json:"-"`
	ExtData_                     [][]byte                `asn1:"-" json:"-"`
}

// CallBarringFeatureList4 represents the ASN.1 type CallBarringFeatureList (SEQUENCE_OF).
type CallBarringFeatureList4 = []CallBarringFeature4

// CallBarringFeature4 represents the ASN.1 type CallBarringFeature (SEQUENCE).
type CallBarringFeature4 struct {
	BasicService *BasicServiceCode4 `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSStatus4         `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64              `asn1:"-" json:"-"`
	ExtPresent_  []bool             `asn1:"-" json:"-"`
	ExtData_     [][]byte           `asn1:"-" json:"-"`
}

// SSData4 represents the ASN.1 type SS-Data (SEQUENCE).
type SSData4 struct {
	SsCode                      *SSCode4               `asn1:",optional" json:"SsCode,omitempty"`
	SsStatus                    *SSStatus4             `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	SsSubscriptionOption        *SSSubscriptionOption4 `asn1:",optional" json:"SsSubscriptionOption,omitempty"`
	BasicServiceGroupList       BasicServiceGroupList4 `asn1:",optional" json:"BasicServiceGroupList,omitempty"`
	BasicServiceGroupListIndef_ bool                   `asn1:"-" json:"-"`
	DefaultPriority             *EMLPPPriority4        `asn1:",optional" json:"DefaultPriority,omitempty"`
	NbrUser                     *MCBearers4            `asn1:"tag:5,context,implicit,optional" json:"NbrUser,omitempty"`
	ExtCount_                   int64                  `asn1:"-" json:"-"`
	ExtPresent_                 []bool                 `asn1:"-" json:"-"`
	ExtData_                    [][]byte               `asn1:"-" json:"-"`
}

// SSSubscriptionOption4 choice constants.
const (
	SSSubscriptionOption4ChoiceCliRestrictionOption = 1
	SSSubscriptionOption4ChoiceOverrideCategory     = 2
)

// SSSubscriptionOption4 represents the ASN.1 CHOICE type SS-SubscriptionOption.
type SSSubscriptionOption4 struct {
	Choice               int
	CliRestrictionOption *CliRestrictionOption4 `json:"CliRestrictionOption,omitempty"`
	OverrideCategory     *OverrideCategory4     `json:"OverrideCategory,omitempty"`
}

// NewSSSubscriptionOption4CliRestrictionOption creates a SSSubscriptionOption4 with the cliRestrictionOption alternative.
func NewSSSubscriptionOption4CliRestrictionOption(v CliRestrictionOption4) SSSubscriptionOption4 {
	return SSSubscriptionOption4{
		Choice:               SSSubscriptionOption4ChoiceCliRestrictionOption,
		CliRestrictionOption: &v,
	}
}

// NewSSSubscriptionOption4OverrideCategory creates a SSSubscriptionOption4 with the overrideCategory alternative.
func NewSSSubscriptionOption4OverrideCategory(v OverrideCategory4) SSSubscriptionOption4 {
	return SSSubscriptionOption4{
		Choice:           SSSubscriptionOption4ChoiceOverrideCategory,
		OverrideCategory: &v,
	}
}

// CliRestrictionOption4 represents the ASN.1 ENUMERATED type CliRestrictionOption.
type CliRestrictionOption4 int64

const (
	CliRestrictionOption4Permanent                  CliRestrictionOption4 = 0
	CliRestrictionOption4TemporaryDefaultRestricted CliRestrictionOption4 = 1
	CliRestrictionOption4TemporaryDefaultAllowed    CliRestrictionOption4 = 2
)

func (v CliRestrictionOption4) String() string {
	switch v {
	case CliRestrictionOption4Permanent:
		return "permanent"
	case CliRestrictionOption4TemporaryDefaultRestricted:
		return "temporaryDefaultRestricted"
	case CliRestrictionOption4TemporaryDefaultAllowed:
		return "temporaryDefaultAllowed"
	default:
		return "unknown"
	}
}

// OverrideCategory4 represents the ASN.1 ENUMERATED type OverrideCategory.
type OverrideCategory4 int64

const (
	OverrideCategory4OverrideEnabled  OverrideCategory4 = 0
	OverrideCategory4OverrideDisabled OverrideCategory4 = 1
)

func (v OverrideCategory4) String() string {
	switch v {
	case OverrideCategory4OverrideEnabled:
		return "overrideEnabled"
	case OverrideCategory4OverrideDisabled:
		return "overrideDisabled"
	default:
		return "unknown"
	}
}

// SSForBSCode4 represents the ASN.1 type SS-ForBS-Code (SEQUENCE).
type SSForBSCode4 struct {
	SsCode           SSCode4            `asn1:""`
	BasicService     *BasicServiceCode4 `asn1:",optional" json:"BasicService,omitempty"`
	LongFTNSupported *struct{}          `asn1:"tag:4,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_        int64              `asn1:"-" json:"-"`
	ExtPresent_      []bool             `asn1:"-" json:"-"`
	ExtData_         [][]byte           `asn1:"-" json:"-"`
}

// GenericServiceInfo4 represents the ASN.1 type GenericServiceInfo (SEQUENCE).
type GenericServiceInfo4 struct {
	SsStatus                SSStatus4              `asn1:""`
	CliRestrictionOption    *CliRestrictionOption4 `asn1:",optional" json:"CliRestrictionOption,omitempty"`
	MaximumEntitledPriority *EMLPPPriority4        `asn1:"tag:0,context,implicit,optional" json:"MaximumEntitledPriority,omitempty"`
	DefaultPriority         *EMLPPPriority4        `asn1:"tag:1,context,implicit,optional" json:"DefaultPriority,omitempty"`
	CcbsFeatureList         CCBSFeatureList4       `asn1:"tag:2,context,implicit,optional" json:"CcbsFeatureList,omitempty"`
	CcbsFeatureListIndef_   bool                   `asn1:"-" json:"-"`
	NbrSB                   *MaxMCBearers4         `asn1:"tag:3,context,implicit,optional" json:"NbrSB,omitempty"`
	NbrUser                 *MCBearers4            `asn1:"tag:4,context,implicit,optional" json:"NbrUser,omitempty"`
	NbrSN                   *MCBearers4            `asn1:"tag:5,context,implicit,optional" json:"NbrSN,omitempty"`
	ExtCount_               int64                  `asn1:"-" json:"-"`
	ExtPresent_             []bool                 `asn1:"-" json:"-"`
	ExtData_                [][]byte               `asn1:"-" json:"-"`
}

// CCBSFeatureList4 represents the ASN.1 type CCBS-FeatureList (SEQUENCE_OF).
type CCBSFeatureList4 = []CCBSFeature4

// CCBSFeature4 represents the ASN.1 type CCBS-Feature (SEQUENCE).
type CCBSFeature4 struct {
	CcbsIndex             *CCBSIndex4            `asn1:"tag:0,context,implicit,optional" json:"CcbsIndex,omitempty"`
	BSubscriberNumber     *ISDNAddressString4    `asn1:"tag:1,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	BSubscriberSubaddress *ISDNSubaddressString4 `asn1:"tag:2,context,implicit,optional" json:"BSubscriberSubaddress,omitempty"`
	BasicServiceGroup     *BasicServiceCode4     `asn1:"tag:3,context,explicit,optional" json:"BasicServiceGroup,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
}

// CCBSIndex4 represents the ASN.1 type CCBS-Index (INTEGER).
type CCBSIndex4 = int64

// InterrogateSSRes4 choice constants.
const (
	InterrogateSSRes4ChoiceSsStatus              = 1
	InterrogateSSRes4ChoiceBasicServiceGroupList = 2
	InterrogateSSRes4ChoiceForwardingFeatureList = 3
	InterrogateSSRes4ChoiceGenericServiceInfo    = 4
)

// InterrogateSSRes4 represents the ASN.1 CHOICE type InterrogateSS-Res.
type InterrogateSSRes4 struct {
	Choice                int
	SsStatus              *SSStatus4             `json:"SsStatus,omitempty"`
	BasicServiceGroupList BasicServiceGroupList4 `json:"BasicServiceGroupList,omitempty"`
	ForwardingFeatureList ForwardingFeatureList4 `json:"ForwardingFeatureList,omitempty"`
	GenericServiceInfo    *GenericServiceInfo4   `json:"GenericServiceInfo,omitempty"`
}

// NewInterrogateSSRes4SsStatus creates a InterrogateSSRes4 with the ss-Status alternative.
func NewInterrogateSSRes4SsStatus(v SSStatus4) InterrogateSSRes4 {
	return InterrogateSSRes4{
		Choice:   InterrogateSSRes4ChoiceSsStatus,
		SsStatus: &v,
	}
}

// NewInterrogateSSRes4BasicServiceGroupList creates a InterrogateSSRes4 with the basicServiceGroupList alternative.
func NewInterrogateSSRes4BasicServiceGroupList(v BasicServiceGroupList4) InterrogateSSRes4 {
	return InterrogateSSRes4{
		Choice:                InterrogateSSRes4ChoiceBasicServiceGroupList,
		BasicServiceGroupList: v,
	}
}

// NewInterrogateSSRes4ForwardingFeatureList creates a InterrogateSSRes4 with the forwardingFeatureList alternative.
func NewInterrogateSSRes4ForwardingFeatureList(v ForwardingFeatureList4) InterrogateSSRes4 {
	return InterrogateSSRes4{
		Choice:                InterrogateSSRes4ChoiceForwardingFeatureList,
		ForwardingFeatureList: v,
	}
}

// NewInterrogateSSRes4GenericServiceInfo creates a InterrogateSSRes4 with the genericServiceInfo alternative.
func NewInterrogateSSRes4GenericServiceInfo(v GenericServiceInfo4) InterrogateSSRes4 {
	return InterrogateSSRes4{
		Choice:             InterrogateSSRes4ChoiceGenericServiceInfo,
		GenericServiceInfo: &v,
	}
}

// USSDArg4 represents the ASN.1 type USSD-Arg (SEQUENCE).
type USSDArg4 struct {
	UssdDataCodingScheme USSDDataCodingScheme4 `asn1:""`
	UssdString           USSDString4           `asn1:""`
	AlertingPattern      *AlertingPattern4     `asn1:",optional" json:"AlertingPattern,omitempty"`
	Msisdn               *ISDNAddressString4   `asn1:"tag:0,context,implicit,optional" json:"Msisdn,omitempty"`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	ExtData_             [][]byte              `asn1:"-" json:"-"`
}

// USSDRes4 represents the ASN.1 type USSD-Res (SEQUENCE).
type USSDRes4 struct {
	UssdDataCodingScheme USSDDataCodingScheme4 `asn1:""`
	UssdString           USSDString4           `asn1:""`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	ExtData_             [][]byte              `asn1:"-" json:"-"`
}

// USSDDataCodingScheme4 represents the ASN.1 type USSD-DataCodingScheme (OCTET_STRING).
type USSDDataCodingScheme4 = []byte

// USSDString4 represents the ASN.1 type USSD-String (OCTET_STRING).
type USSDString4 = []byte

// Password4 represents the ASN.1 type Password (NumericString).
type Password4 = string

// GuidanceInfo4 represents the ASN.1 ENUMERATED type GuidanceInfo.
type GuidanceInfo4 int64

const (
	GuidanceInfo4EnterPW         GuidanceInfo4 = 0
	GuidanceInfo4EnterNewPW      GuidanceInfo4 = 1
	GuidanceInfo4EnterNewPWAgain GuidanceInfo4 = 2
)

func (v GuidanceInfo4) String() string {
	switch v {
	case GuidanceInfo4EnterPW:
		return "enterPW"
	case GuidanceInfo4EnterNewPW:
		return "enterNewPW"
	case GuidanceInfo4EnterNewPWAgain:
		return "enterNewPW-Again"
	default:
		return "unknown"
	}
}

// SSList4 represents the ASN.1 type SS-List (SEQUENCE_OF).
type SSList4 = []SSCode4

// SSInfoList4 represents the ASN.1 type SS-InfoList (SEQUENCE_OF).
type SSInfoList4 = []SSInfo4

// BasicServiceGroupList4 represents the ASN.1 type BasicServiceGroupList (SEQUENCE_OF).
type BasicServiceGroupList4 = []BasicServiceCode4

// SSInvocationNotificationArg4 represents the ASN.1 type SS-InvocationNotificationArg (SEQUENCE).
type SSInvocationNotificationArg4 struct {
	Imsi                       IMSI4                 `asn1:"tag:0,context,implicit"`
	Msisdn                     ISDNAddressString4    `asn1:"tag:1,context,implicit"`
	SsEvent                    SSCode4               `asn1:"tag:2,context,implicit"`
	SsEventSpecification       SSEventSpecification4 `asn1:"tag:3,context,implicit,optional" json:"SsEventSpecification,omitempty"`
	SsEventSpecificationIndef_ bool                  `asn1:"-" json:"-"`
	ExtensionContainer         *ExtensionContainer4  `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	BSubscriberNumber          *ISDNAddressString4   `asn1:"tag:5,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	CcbsRequestState           *CCBSRequestState4    `asn1:"tag:6,context,implicit,optional" json:"CcbsRequestState,omitempty"`
	ExtCount_                  int64                 `asn1:"-" json:"-"`
	ExtPresent_                []bool                `asn1:"-" json:"-"`
	ExtData_                   [][]byte              `asn1:"-" json:"-"`
}

// CCBSRequestState4 represents the ASN.1 ENUMERATED type CCBS-RequestState.
type CCBSRequestState4 int64

const (
	CCBSRequestState4Request   CCBSRequestState4 = 0
	CCBSRequestState4Recall    CCBSRequestState4 = 1
	CCBSRequestState4Active    CCBSRequestState4 = 2
	CCBSRequestState4Completed CCBSRequestState4 = 3
	CCBSRequestState4Suspended CCBSRequestState4 = 4
	CCBSRequestState4Frozen    CCBSRequestState4 = 5
	CCBSRequestState4Deleted   CCBSRequestState4 = 6
)

func (v CCBSRequestState4) String() string {
	switch v {
	case CCBSRequestState4Request:
		return "request"
	case CCBSRequestState4Recall:
		return "recall"
	case CCBSRequestState4Active:
		return "active"
	case CCBSRequestState4Completed:
		return "completed"
	case CCBSRequestState4Suspended:
		return "suspended"
	case CCBSRequestState4Frozen:
		return "frozen"
	case CCBSRequestState4Deleted:
		return "deleted"
	default:
		return "unknown"
	}
}

// SSInvocationNotificationRes4 represents the ASN.1 type SS-InvocationNotificationRes (SEQUENCE).
type SSInvocationNotificationRes4 struct {
	ExtensionContainer *ExtensionContainer4 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SSEventSpecification4 represents the ASN.1 type SS-EventSpecification (SEQUENCE_OF).
type SSEventSpecification4 = []AddressString4

// RegisterCCEntryArg4 represents the ASN.1 type RegisterCC-EntryArg (SEQUENCE).
type RegisterCCEntryArg4 struct {
	SsCode      SSCode4    `asn1:"tag:0,context,implicit"`
	CcbsData    *CCBSData4 `asn1:"tag:1,context,implicit,optional" json:"CcbsData,omitempty"`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	ExtData_    [][]byte   `asn1:"-" json:"-"`
}

// CCBSData4 represents the ASN.1 type CCBS-Data (SEQUENCE).
type CCBSData4 struct {
	CcbsFeature       CCBSFeature4        `asn1:"tag:0,context,implicit"`
	TranslatedBNumber ISDNAddressString4  `asn1:"tag:1,context,implicit"`
	ServiceIndicator  *ServiceIndicator4  `asn1:"tag:2,context,implicit,optional" json:"ServiceIndicator,omitempty"`
	CallInfo          ExternalSignalInfo4 `asn1:"tag:3,context,implicit"`
	NetworkSignalInfo ExternalSignalInfo4 `asn1:"tag:4,context,implicit"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ServiceIndicator4 represents the ASN.1 type ServiceIndicator (BIT_STRING).
type ServiceIndicator4 = runtime.BitString

// RegisterCCEntryRes4 represents the ASN.1 type RegisterCC-EntryRes (SEQUENCE).
type RegisterCCEntryRes4 struct {
	CcbsFeature *CCBSFeature4 `asn1:"tag:0,context,implicit,optional" json:"CcbsFeature,omitempty"`
	ExtCount_   int64         `asn1:"-" json:"-"`
	ExtPresent_ []bool        `asn1:"-" json:"-"`
	ExtData_    [][]byte      `asn1:"-" json:"-"`
}

// EraseCCEntryArg4 represents the ASN.1 type EraseCC-EntryArg (SEQUENCE).
type EraseCCEntryArg4 struct {
	SsCode      SSCode4     `asn1:"tag:0,context,implicit"`
	CcbsIndex   *CCBSIndex4 `asn1:"tag:1,context,implicit,optional" json:"CcbsIndex,omitempty"`
	ExtCount_   int64       `asn1:"-" json:"-"`
	ExtPresent_ []bool      `asn1:"-" json:"-"`
	ExtData_    [][]byte    `asn1:"-" json:"-"`
}

// EraseCCEntryRes4 represents the ASN.1 type EraseCC-EntryRes (SEQUENCE).
type EraseCCEntryRes4 struct {
	SsCode      SSCode4    `asn1:"tag:0,context,implicit"`
	SsStatus    *SSStatus4 `asn1:"tag:1,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	ExtData_    [][]byte   `asn1:"-" json:"-"`
}

// MarshalBER encodes RegisterSSArg4 to BER format.
func (v *RegisterSSArg4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	children = append(children, enc_sscode...)
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.ForwardedToNumber != nil {
		enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		enc_forwardedtonumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_forwardedtonumber)
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		enc_forwardedtosubaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_forwardedtosubaddress)
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.NoReplyConditionTime != nil {
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		enc_noreplyconditiontime = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_noreplyconditiontime)
		children = append(children, enc_noreplyconditiontime...)
	}
	if v.DefaultPriority != nil {
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		enc_defaultpriority = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_defaultpriority)
		children = append(children, enc_defaultpriority...)
	}
	if v.NbrUser != nil {
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		enc_nbruser = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_nbruser)
		children = append(children, enc_nbruser...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		enc_longftnsupported = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_longftnsupported)
		children = append(children, enc_longftnsupported...)
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

// MarshalDER encodes RegisterSSArg4 to DER format.
func (v *RegisterSSArg4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RegisterSSArg4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RegisterSSArg4 from BER/DER format.
func (v *RegisterSSArg4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RegisterSSArg4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterSSArg4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	val_sscode, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	v.SsCode = SSCode4(val_sscode)
	offset += n
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode4)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode4
				if unmErr := dec_basicservice.UnmarshalBER(content[offset : offset+n_basicservice]); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				offset += n_basicservice
			}
		}
	}
	// Decode forwardedToNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_forwardedtonumber, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToNumber: %w", err)
				}
				if decodedTag_forwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_forwardedtonumber.Number != 4 {
					return fmt.Errorf("decoding forwardedToNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtonumber)
				}
				tmp_forwardedtonumber := AddressString4(rawVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				offset += n_forwardedtonumber
			}
		}
	}
	// Decode forwardedToSubaddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_forwardedtosubaddress, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToSubaddress: %w", err)
				}
				if decodedTag_forwardedtosubaddress.Class != tag.ClassContextSpecific || decodedTag_forwardedtosubaddress.Number != 6 {
					return fmt.Errorf("decoding forwardedToSubaddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtosubaddress)
				}
				tmp_forwardedtosubaddress := ISDNSubaddressString4(rawVal_forwardedtosubaddress)
				v.ForwardedToSubaddress = &tmp_forwardedtosubaddress
				offset += n_forwardedtosubaddress
			}
		}
	}
	// Decode noReplyConditionTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_noreplyconditiontime, n_noreplyconditiontime, rawVal_noreplyconditiontime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding noReplyConditionTime: %w", err)
				}
				if decodedTag_noreplyconditiontime.Class != tag.ClassContextSpecific || decodedTag_noreplyconditiontime.Number != 5 || decodedTag_noreplyconditiontime.Constructed != false {
					return fmt.Errorf("decoding noReplyConditionTime: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_noreplyconditiontime)
				}
				decVal_noreplyconditiontime, intErr := ber.DecodeIntegerValue(rawVal_noreplyconditiontime)
				if intErr != nil {
					return fmt.Errorf("decoding noReplyConditionTime: %w", intErr)
				}
				tmp_noreplyconditiontime := NoReplyConditionTime4(decVal_noreplyconditiontime)
				v.NoReplyConditionTime = &tmp_noreplyconditiontime
				offset += n_noreplyconditiontime
			}
		}
	}
	// Decode defaultPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_defaultpriority, n_defaultpriority, rawVal_defaultpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding defaultPriority: %w", err)
				}
				if decodedTag_defaultpriority.Class != tag.ClassContextSpecific || decodedTag_defaultpriority.Number != 7 || decodedTag_defaultpriority.Constructed != false {
					return fmt.Errorf("decoding defaultPriority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_defaultpriority)
				}
				decVal_defaultpriority, intErr := ber.DecodeIntegerValue(rawVal_defaultpriority)
				if intErr != nil {
					return fmt.Errorf("decoding defaultPriority: %w", intErr)
				}
				tmp_defaultpriority := EMLPPPriority4(decVal_defaultpriority)
				v.DefaultPriority = &tmp_defaultpriority
				offset += n_defaultpriority
			}
		}
	}
	// Decode nbrUser
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nbrUser: %w", err)
				}
				if decodedTag_nbruser.Class != tag.ClassContextSpecific || decodedTag_nbruser.Number != 8 || decodedTag_nbruser.Constructed != false {
					return fmt.Errorf("decoding nbrUser: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbruser)
				}
				decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
				if intErr != nil {
					return fmt.Errorf("decoding nbrUser: %w", intErr)
				}
				tmp_nbruser := MCBearers4(decVal_nbruser)
				v.NbrUser = &tmp_nbruser
				offset += n_nbruser
			}
		}
	}
	// Decode longFTN-Supported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_longftnsupported, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longFTN-Supported: %w", err)
				}
				if decodedTag_longftnsupported.Class != tag.ClassContextSpecific || decodedTag_longftnsupported.Number != 9 || decodedTag_longftnsupported.Constructed != false {
					return fmt.Errorf("decoding longFTN-Supported: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longftnsupported)
				}
				if len(rawVal_longftnsupported) != 0 {
					return fmt.Errorf("decoding longFTN-Supported: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_longftnsupported))
				}
				v.LongFTNSupported = &struct{}{}
				offset += n_longftnsupported
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterSSArg4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSInfo4 to BER format.
func (v *SSInfo4) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SSInfo4ChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("choice SSInfo4: forwardingInfo is nil")
		}
		enc_0, err := v.ForwardingInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingInfo: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case SSInfo4ChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("choice SSInfo4: callBarringInfo is nil")
		}
		enc_1, err := v.CallBarringInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding callBarringInfo: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		return enc_1, nil
	case SSInfo4ChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("choice SSInfo4: ss-Data is nil")
		}
		enc_2, err := v.SsData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ss-Data: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSInfo4", v.Choice)
	}
}

// MarshalDER encodes SSInfo4 to DER format.
func (v *SSInfo4) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case SSInfo4ChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("choice SSInfo4: forwardingInfo is nil")
		}
		enc_der_0, err := v.ForwardingInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingInfo: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		if derErr := ber.ValidateDERElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding forwardingInfo as DER: %w", derErr)
		}
		return enc_der_0, nil
	case SSInfo4ChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("choice SSInfo4: callBarringInfo is nil")
		}
		enc_der_1, err := v.CallBarringInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding callBarringInfo: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		if derErr := ber.ValidateDERElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding callBarringInfo as DER: %w", derErr)
		}
		return enc_der_1, nil
	case SSInfo4ChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("choice SSInfo4: ss-Data is nil")
		}
		enc_der_2, err := v.SsData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ss-Data: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_der_2)
		if derErr := ber.ValidateDERElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding ss-Data as DER: %w", derErr)
		}
		return enc_der_2, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSInfo4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSInfo4 from BER/DER format.
func (v *SSInfo4) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSInfo4 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSInfo4: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SSInfo4 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInfo4", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = SSInfo4ChoiceForwardingInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding forwardingInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ForwardingInfo4
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding forwardingInfo: %w", unmErr)
		}
		v.ForwardingInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = SSInfo4ChoiceCallBarringInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding callBarringInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CallBarringInfo4
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding callBarringInfo: %w", unmErr)
		}
		v.CallBarringInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = SSInfo4ChoiceSsData
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ss-Data: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SSData4
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding ss-Data: %w", unmErr)
		}
		v.SsData = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SSInfo4 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ForwardingInfo4 to BER format.
func (v *ForwardingInfo4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		children = append(children, enc_sscode...)
	}
	enc_forwardingfeaturelist, err := MarshalBERForwardingFeatureList4(v.ForwardingFeatureList)
	if err != nil {
		return nil, fmt.Errorf("encoding forwardingFeatureList: %w", err)
	}
	children = append(children, enc_forwardingfeaturelist...)
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

// MarshalDER encodes ForwardingInfo4 to DER format.
func (v *ForwardingInfo4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ForwardingFeatureListIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ForwardingInfo4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingInfo4 from BER/DER format.
func (v *ForwardingInfo4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardingInfo4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingInfo4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_sscode, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				tmp_sscode := SSCode4(val_sscode)
				v.SsCode = &tmp_sscode
				offset += n
			}
		}
	}
	// Decode forwardingFeatureList
	if offset >= len(content) {
		return fmt.Errorf("missing required field forwardingFeatureList")
	}
	v.ForwardingFeatureListIndef_ = false
	// Decode nested SEQUENCE_OF (ForwardingFeatureList4)
	_, n_forwardingfeaturelist, _, tlvErr_forwardingfeaturelist := ber.DecodeTLV(content[offset:])
	if tlvErr_forwardingfeaturelist != nil {
		return fmt.Errorf("decoding forwardingFeatureList: %w", tlvErr_forwardingfeaturelist)
	}
	tlv_forwardingfeaturelist := content[offset : offset+n_forwardingfeaturelist]
	{
		_, tagSz_, _ := ber.DecodeTag(tlv_forwardingfeaturelist)
		if tagSz_ < len(tlv_forwardingfeaturelist) && tlv_forwardingfeaturelist[tagSz_] == 0x80 {
			v.ForwardingFeatureListIndef_ = true
		}
	}
	dec_forwardingfeaturelist, unmErr := UnmarshalBERForwardingFeatureList4(tlv_forwardingfeaturelist)
	if unmErr != nil {
		return fmt.Errorf("decoding forwardingFeatureList: %w", unmErr)
	}
	v.ForwardingFeatureList = dec_forwardingfeaturelist
	offset += n_forwardingfeaturelist
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingInfo4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERForwardingFeatureList4 encodes a ForwardingFeatureList4 list to BER.
func MarshalBERForwardingFeatureList4(list ForwardingFeatureList4) ([]byte, error) {
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

// UnmarshalBERForwardingFeatureList4 decodes a ForwardingFeatureList4 list from BER.
func UnmarshalBERForwardingFeatureList4(data []byte) (ForwardingFeatureList4, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ForwardingFeatureList4: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ForwardingFeatureList4", Cause: ber.ErrExtraData}
	}
	var result ForwardingFeatureList4
	offset := 0
	for offset < len(content) {
		var elem ForwardingFeature4
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

// MarshalBER encodes ForwardingFeature4 to BER format.
func (v *ForwardingFeature4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		enc_ssstatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_ssstatus)
		children = append(children, enc_ssstatus...)
	}
	if v.ForwardedToNumber != nil {
		enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		enc_forwardedtonumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_forwardedtonumber)
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		enc_forwardedtosubaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, false, enc_forwardedtosubaddress)
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		enc_forwardingoptions = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_forwardingoptions)
		children = append(children, enc_forwardingoptions...)
	}
	if v.NoReplyConditionTime != nil {
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		enc_noreplyconditiontime = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, false, enc_noreplyconditiontime)
		children = append(children, enc_noreplyconditiontime...)
	}
	if v.LongForwardedToNumber != nil {
		enc_longforwardedtonumber := ber.EncodeOctetString([]byte(*v.LongForwardedToNumber))
		enc_longforwardedtonumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, false, enc_longforwardedtonumber)
		children = append(children, enc_longforwardedtonumber...)
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

// MarshalDER encodes ForwardingFeature4 to DER format.
func (v *ForwardingFeature4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding ForwardingFeature4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingFeature4 from BER/DER format.
func (v *ForwardingFeature4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardingFeature4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingFeature4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode4)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode4
				if unmErr := dec_basicservice.UnmarshalBER(content[offset : offset+n_basicservice]); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				offset += n_basicservice
			}
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
				}
				tmp_ssstatus := SSStatus4(rawVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				offset += n_ssstatus
			}
		}
	}
	// Decode forwardedToNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_forwardedtonumber, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToNumber: %w", err)
				}
				if decodedTag_forwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_forwardedtonumber.Number != 5 {
					return fmt.Errorf("decoding forwardedToNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtonumber)
				}
				tmp_forwardedtonumber := ISDNAddressString4(rawVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				offset += n_forwardedtonumber
			}
		}
	}
	// Decode forwardedToSubaddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_forwardedtosubaddress, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToSubaddress: %w", err)
				}
				if decodedTag_forwardedtosubaddress.Class != tag.ClassContextSpecific || decodedTag_forwardedtosubaddress.Number != 8 {
					return fmt.Errorf("decoding forwardedToSubaddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtosubaddress)
				}
				tmp_forwardedtosubaddress := ISDNSubaddressString4(rawVal_forwardedtosubaddress)
				v.ForwardedToSubaddress = &tmp_forwardedtosubaddress
				offset += n_forwardedtosubaddress
			}
		}
	}
	// Decode forwardingOptions
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_forwardingoptions, n_forwardingoptions, rawVal_forwardingoptions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardingOptions: %w", err)
				}
				if decodedTag_forwardingoptions.Class != tag.ClassContextSpecific || decodedTag_forwardingoptions.Number != 6 {
					return fmt.Errorf("decoding forwardingOptions: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardingoptions)
				}
				tmp_forwardingoptions := ForwardingOptions4(rawVal_forwardingoptions)
				v.ForwardingOptions = &tmp_forwardingoptions
				offset += n_forwardingoptions
			}
		}
	}
	// Decode noReplyConditionTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_noreplyconditiontime, n_noreplyconditiontime, rawVal_noreplyconditiontime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding noReplyConditionTime: %w", err)
				}
				if decodedTag_noreplyconditiontime.Class != tag.ClassContextSpecific || decodedTag_noreplyconditiontime.Number != 7 || decodedTag_noreplyconditiontime.Constructed != false {
					return fmt.Errorf("decoding noReplyConditionTime: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_noreplyconditiontime)
				}
				decVal_noreplyconditiontime, intErr := ber.DecodeIntegerValue(rawVal_noreplyconditiontime)
				if intErr != nil {
					return fmt.Errorf("decoding noReplyConditionTime: %w", intErr)
				}
				tmp_noreplyconditiontime := NoReplyConditionTime4(decVal_noreplyconditiontime)
				v.NoReplyConditionTime = &tmp_noreplyconditiontime
				offset += n_noreplyconditiontime
			}
		}
	}
	// Decode longForwardedToNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_longforwardedtonumber, n_longforwardedtonumber, rawVal_longforwardedtonumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longForwardedToNumber: %w", err)
				}
				if decodedTag_longforwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_longforwardedtonumber.Number != 9 {
					return fmt.Errorf("decoding longForwardedToNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longforwardedtonumber)
				}
				tmp_longforwardedtonumber := FTNAddressString4(rawVal_longforwardedtonumber)
				v.LongForwardedToNumber = &tmp_longforwardedtonumber
				offset += n_longforwardedtonumber
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingFeature4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CallBarringInfo4 to BER format.
func (v *CallBarringInfo4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		children = append(children, enc_sscode...)
	}
	enc_callbarringfeaturelist, err := MarshalBERCallBarringFeatureList4(v.CallBarringFeatureList)
	if err != nil {
		return nil, fmt.Errorf("encoding callBarringFeatureList: %w", err)
	}
	children = append(children, enc_callbarringfeaturelist...)
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

// MarshalDER encodes CallBarringInfo4 to DER format.
func (v *CallBarringInfo4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.CallBarringFeatureListIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CallBarringInfo4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CallBarringInfo4 from BER/DER format.
func (v *CallBarringInfo4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CallBarringInfo4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarringInfo4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_sscode, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				tmp_sscode := SSCode4(val_sscode)
				v.SsCode = &tmp_sscode
				offset += n
			}
		}
	}
	// Decode callBarringFeatureList
	if offset >= len(content) {
		return fmt.Errorf("missing required field callBarringFeatureList")
	}
	v.CallBarringFeatureListIndef_ = false
	// Decode nested SEQUENCE_OF (CallBarringFeatureList4)
	_, n_callbarringfeaturelist, _, tlvErr_callbarringfeaturelist := ber.DecodeTLV(content[offset:])
	if tlvErr_callbarringfeaturelist != nil {
		return fmt.Errorf("decoding callBarringFeatureList: %w", tlvErr_callbarringfeaturelist)
	}
	tlv_callbarringfeaturelist := content[offset : offset+n_callbarringfeaturelist]
	{
		_, tagSz_, _ := ber.DecodeTag(tlv_callbarringfeaturelist)
		if tagSz_ < len(tlv_callbarringfeaturelist) && tlv_callbarringfeaturelist[tagSz_] == 0x80 {
			v.CallBarringFeatureListIndef_ = true
		}
	}
	dec_callbarringfeaturelist, unmErr := UnmarshalBERCallBarringFeatureList4(tlv_callbarringfeaturelist)
	if unmErr != nil {
		return fmt.Errorf("decoding callBarringFeatureList: %w", unmErr)
	}
	v.CallBarringFeatureList = dec_callbarringfeaturelist
	offset += n_callbarringfeaturelist
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CallBarringInfo4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERCallBarringFeatureList4 encodes a CallBarringFeatureList4 list to BER.
func MarshalBERCallBarringFeatureList4(list CallBarringFeatureList4) ([]byte, error) {
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

// UnmarshalBERCallBarringFeatureList4 decodes a CallBarringFeatureList4 list from BER.
func UnmarshalBERCallBarringFeatureList4(data []byte) (CallBarringFeatureList4, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding CallBarringFeatureList4: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CallBarringFeatureList4", Cause: ber.ErrExtraData}
	}
	var result CallBarringFeatureList4
	offset := 0
	for offset < len(content) {
		var elem CallBarringFeature4
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

// MarshalBER encodes CallBarringFeature4 to BER format.
func (v *CallBarringFeature4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		enc_ssstatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_ssstatus)
		children = append(children, enc_ssstatus...)
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

// MarshalDER encodes CallBarringFeature4 to DER format.
func (v *CallBarringFeature4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CallBarringFeature4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CallBarringFeature4 from BER/DER format.
func (v *CallBarringFeature4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CallBarringFeature4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarringFeature4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode4)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode4
				if unmErr := dec_basicservice.UnmarshalBER(content[offset : offset+n_basicservice]); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				offset += n_basicservice
			}
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
				}
				tmp_ssstatus := SSStatus4(rawVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				offset += n_ssstatus
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CallBarringFeature4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSData4 to BER format.
func (v *SSData4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		children = append(children, enc_sscode...)
	}
	if v.SsStatus != nil {
		enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		enc_ssstatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_ssstatus)
		children = append(children, enc_ssstatus...)
	}
	if v.SsSubscriptionOption != nil {
		enc_sssubscriptionoption, err := v.SsSubscriptionOption.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ss-SubscriptionOption: %w", err)
		}
		children = append(children, enc_sssubscriptionoption...)
	}
	if v.BasicServiceGroupList != nil {
		enc_basicservicegrouplist, err := MarshalBERBasicServiceGroupList4(v.BasicServiceGroupList)
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList: %w", err)
		}
		children = append(children, enc_basicservicegrouplist...)
	}
	if v.DefaultPriority != nil {
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		children = append(children, enc_defaultpriority...)
	}
	if v.NbrUser != nil {
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		enc_nbruser = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_nbruser)
		children = append(children, enc_nbruser...)
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

// MarshalDER encodes SSData4 to DER format.
func (v *SSData4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.BasicServiceGroupListIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSData4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSData4 from BER/DER format.
func (v *SSData4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSData4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSData4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_sscode, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				tmp_sscode := SSCode4(val_sscode)
				v.SsCode = &tmp_sscode
				offset += n
			}
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
				}
				tmp_ssstatus := SSStatus4(rawVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				offset += n_ssstatus
			}
		}
	}
	// Decode ss-SubscriptionOption
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
				// Decode nested CHOICE (SSSubscriptionOption4)
				_, n_sssubscriptionoption, _, tlvErr_sssubscriptionoption := ber.DecodeTLV(content[offset:])
				if tlvErr_sssubscriptionoption != nil {
					return fmt.Errorf("decoding ss-SubscriptionOption: %w", tlvErr_sssubscriptionoption)
				}
				var dec_sssubscriptionoption SSSubscriptionOption4
				if unmErr := dec_sssubscriptionoption.UnmarshalBER(content[offset : offset+n_sssubscriptionoption]); unmErr != nil {
					return fmt.Errorf("decoding ss-SubscriptionOption: %w", unmErr)
				}
				v.SsSubscriptionOption = &dec_sssubscriptionoption
				offset += n_sssubscriptionoption
			}
		}
	}
	// Decode basicServiceGroupList
	v.BasicServiceGroupListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (BasicServiceGroupList4)
				_, n_basicservicegrouplist, _, tlvErr_basicservicegrouplist := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservicegrouplist != nil {
					return fmt.Errorf("decoding basicServiceGroupList: %w", tlvErr_basicservicegrouplist)
				}
				tlv_basicservicegrouplist := content[offset : offset+n_basicservicegrouplist]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_basicservicegrouplist)
					if tagSz_ < len(tlv_basicservicegrouplist) && tlv_basicservicegrouplist[tagSz_] == 0x80 {
						v.BasicServiceGroupListIndef_ = true
					}
				}
				dec_basicservicegrouplist, unmErr := UnmarshalBERBasicServiceGroupList4(tlv_basicservicegrouplist)
				if unmErr != nil {
					return fmt.Errorf("decoding basicServiceGroupList: %w", unmErr)
				}
				v.BasicServiceGroupList = dec_basicservicegrouplist
				offset += n_basicservicegrouplist
			}
		}
	}
	// Decode defaultPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				val_defaultpriority, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding defaultPriority: %w", err)
				}
				tmp_defaultpriority := EMLPPPriority4(val_defaultpriority)
				v.DefaultPriority = &tmp_defaultpriority
				offset += n
			}
		}
	}
	// Decode nbrUser
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nbrUser: %w", err)
				}
				if decodedTag_nbruser.Class != tag.ClassContextSpecific || decodedTag_nbruser.Number != 5 || decodedTag_nbruser.Constructed != false {
					return fmt.Errorf("decoding nbrUser: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbruser)
				}
				decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
				if intErr != nil {
					return fmt.Errorf("decoding nbrUser: %w", intErr)
				}
				tmp_nbruser := MCBearers4(decVal_nbruser)
				v.NbrUser = &tmp_nbruser
				offset += n_nbruser
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSData4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSSubscriptionOption4 to BER format.
func (v *SSSubscriptionOption4) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SSSubscriptionOption4ChoiceCliRestrictionOption:
		if v.CliRestrictionOption == nil {
			return nil, fmt.Errorf("choice SSSubscriptionOption4: cliRestrictionOption is nil")
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_0)
		return enc_0, nil
	case SSSubscriptionOption4ChoiceOverrideCategory:
		if v.OverrideCategory == nil {
			return nil, fmt.Errorf("choice SSSubscriptionOption4: overrideCategory is nil")
		}
		enc_1 := ber.EncodeEnumerated(int64(*v.OverrideCategory))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSSubscriptionOption4", v.Choice)
	}
}

// MarshalDER encodes SSSubscriptionOption4 to DER format.
func (v *SSSubscriptionOption4) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSSubscriptionOption4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSSubscriptionOption4 from BER/DER format.
func (v *SSSubscriptionOption4) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSSubscriptionOption4 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSSubscriptionOption4: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SSSubscriptionOption4 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSubscriptionOption4", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOption4ChoiceCliRestrictionOption
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cliRestrictionOption: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding cliRestrictionOption: %w", intErr)
		}
		tmp := CliRestrictionOption4(decVal)
		v.CliRestrictionOption = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOption4ChoiceOverrideCategory
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding overrideCategory: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding overrideCategory: %w", intErr)
		}
		tmp := OverrideCategory4(decVal)
		v.OverrideCategory = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SSSubscriptionOption4 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SSForBSCode4 to BER format.
func (v *SSForBSCode4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	children = append(children, enc_sscode...)
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		enc_longftnsupported = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_longftnsupported)
		children = append(children, enc_longftnsupported...)
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

// MarshalDER encodes SSForBSCode4 to DER format.
func (v *SSForBSCode4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSForBSCode4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSForBSCode4 from BER/DER format.
func (v *SSForBSCode4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSForBSCode4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSForBSCode4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	val_sscode, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	v.SsCode = SSCode4(val_sscode)
	offset += n
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode4)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode4
				if unmErr := dec_basicservice.UnmarshalBER(content[offset : offset+n_basicservice]); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				offset += n_basicservice
			}
		}
	}
	// Decode longFTN-Supported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_longftnsupported, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longFTN-Supported: %w", err)
				}
				if decodedTag_longftnsupported.Class != tag.ClassContextSpecific || decodedTag_longftnsupported.Number != 4 || decodedTag_longftnsupported.Constructed != false {
					return fmt.Errorf("decoding longFTN-Supported: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longftnsupported)
				}
				if len(rawVal_longftnsupported) != 0 {
					return fmt.Errorf("decoding longFTN-Supported: %w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_longftnsupported))
				}
				v.LongFTNSupported = &struct{}{}
				offset += n_longftnsupported
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSForBSCode4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GenericServiceInfo4 to BER format.
func (v *GenericServiceInfo4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	children = append(children, enc_ssstatus...)
	if v.CliRestrictionOption != nil {
		enc_clirestrictionoption := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		children = append(children, enc_clirestrictionoption...)
	}
	if v.MaximumEntitledPriority != nil {
		enc_maximumentitledpriority := ber.EncodeInteger(int64(*v.MaximumEntitledPriority))
		enc_maximumentitledpriority = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_maximumentitledpriority)
		children = append(children, enc_maximumentitledpriority...)
	}
	if v.DefaultPriority != nil {
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		enc_defaultpriority = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_defaultpriority)
		children = append(children, enc_defaultpriority...)
	}
	if v.CcbsFeatureList != nil {
		enc_ccbsfeaturelist, err := MarshalBERCCBSFeatureList4(v.CcbsFeatureList)
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-FeatureList: %w", err)
		}
		if v.CcbsFeatureListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_ccbsfeaturelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_ccbsfeaturelist = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
		} else {
			enc_ccbsfeaturelist = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_ccbsfeaturelist)
		}
		children = append(children, enc_ccbsfeaturelist...)
	}
	if v.NbrSB != nil {
		enc_nbrsb := ber.EncodeInteger(int64(*v.NbrSB))
		enc_nbrsb = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, false, enc_nbrsb)
		children = append(children, enc_nbrsb...)
	}
	if v.NbrUser != nil {
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		enc_nbruser = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, false, enc_nbruser)
		children = append(children, enc_nbruser...)
	}
	if v.NbrSN != nil {
		enc_nbrsn := ber.EncodeInteger(int64(*v.NbrSN))
		enc_nbrsn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_nbrsn)
		children = append(children, enc_nbrsn...)
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

// MarshalDER encodes GenericServiceInfo4 to DER format.
func (v *GenericServiceInfo4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.CcbsFeatureListIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding GenericServiceInfo4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes GenericServiceInfo4 from BER/DER format.
func (v *GenericServiceInfo4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding GenericServiceInfo4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GenericServiceInfo4", Cause: ber.ErrExtraData}
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
	v.SsStatus = SSStatus4(val_ssstatus)
	offset += n
	// Decode cliRestrictionOption
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_clirestrictionoption, n, err := ber.DecodeInteger(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding cliRestrictionOption: %w", err)
				}
				tmp_clirestrictionoption := CliRestrictionOption4(val_clirestrictionoption)
				v.CliRestrictionOption = &tmp_clirestrictionoption
				offset += n
			}
		}
	}
	// Decode maximumEntitledPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_maximumentitledpriority, n_maximumentitledpriority, rawVal_maximumentitledpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding maximumEntitledPriority: %w", err)
				}
				if decodedTag_maximumentitledpriority.Class != tag.ClassContextSpecific || decodedTag_maximumentitledpriority.Number != 0 || decodedTag_maximumentitledpriority.Constructed != false {
					return fmt.Errorf("decoding maximumEntitledPriority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_maximumentitledpriority)
				}
				decVal_maximumentitledpriority, intErr := ber.DecodeIntegerValue(rawVal_maximumentitledpriority)
				if intErr != nil {
					return fmt.Errorf("decoding maximumEntitledPriority: %w", intErr)
				}
				tmp_maximumentitledpriority := EMLPPPriority4(decVal_maximumentitledpriority)
				v.MaximumEntitledPriority = &tmp_maximumentitledpriority
				offset += n_maximumentitledpriority
			}
		}
	}
	// Decode defaultPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_defaultpriority, n_defaultpriority, rawVal_defaultpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding defaultPriority: %w", err)
				}
				if decodedTag_defaultpriority.Class != tag.ClassContextSpecific || decodedTag_defaultpriority.Number != 1 || decodedTag_defaultpriority.Constructed != false {
					return fmt.Errorf("decoding defaultPriority: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_defaultpriority)
				}
				decVal_defaultpriority, intErr := ber.DecodeIntegerValue(rawVal_defaultpriority)
				if intErr != nil {
					return fmt.Errorf("decoding defaultPriority: %w", intErr)
				}
				tmp_defaultpriority := EMLPPPriority4(decVal_defaultpriority)
				v.DefaultPriority = &tmp_defaultpriority
				offset += n_defaultpriority
			}
		}
	}
	// Decode ccbs-FeatureList
	v.CcbsFeatureListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_ccbsfeaturelist, n_ccbsfeaturelist, rawVal_ccbsfeaturelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-FeatureList: %w", err)
				}
				if decodedTag_ccbsfeaturelist.Class != tag.ClassContextSpecific || decodedTag_ccbsfeaturelist.Number != 2 || decodedTag_ccbsfeaturelist.Constructed != true {
					return fmt.Errorf("decoding ccbs-FeatureList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsfeaturelist)
				}
				reconstructed_ccbsfeaturelist := ber.EncodeSequence(rawVal_ccbsfeaturelist)
				dec_ccbsfeaturelist, unmErr := UnmarshalBERCCBSFeatureList4(reconstructed_ccbsfeaturelist)
				if unmErr != nil {
					return fmt.Errorf("decoding ccbs-FeatureList: %w", unmErr)
				}
				v.CcbsFeatureList = dec_ccbsfeaturelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.CcbsFeatureListIndef_ = true
					}
				}
				offset += n_ccbsfeaturelist
			}
		}
	}
	// Decode nbrSB
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_nbrsb, n_nbrsb, rawVal_nbrsb, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nbrSB: %w", err)
				}
				if decodedTag_nbrsb.Class != tag.ClassContextSpecific || decodedTag_nbrsb.Number != 3 || decodedTag_nbrsb.Constructed != false {
					return fmt.Errorf("decoding nbrSB: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbrsb)
				}
				decVal_nbrsb, intErr := ber.DecodeIntegerValue(rawVal_nbrsb)
				if intErr != nil {
					return fmt.Errorf("decoding nbrSB: %w", intErr)
				}
				tmp_nbrsb := MaxMCBearers4(decVal_nbrsb)
				v.NbrSB = &tmp_nbrsb
				offset += n_nbrsb
			}
		}
	}
	// Decode nbrUser
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nbrUser: %w", err)
				}
				if decodedTag_nbruser.Class != tag.ClassContextSpecific || decodedTag_nbruser.Number != 4 || decodedTag_nbruser.Constructed != false {
					return fmt.Errorf("decoding nbrUser: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbruser)
				}
				decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
				if intErr != nil {
					return fmt.Errorf("decoding nbrUser: %w", intErr)
				}
				tmp_nbruser := MCBearers4(decVal_nbruser)
				v.NbrUser = &tmp_nbruser
				offset += n_nbruser
			}
		}
	}
	// Decode nbrSN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_nbrsn, n_nbrsn, rawVal_nbrsn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nbrSN: %w", err)
				}
				if decodedTag_nbrsn.Class != tag.ClassContextSpecific || decodedTag_nbrsn.Number != 5 || decodedTag_nbrsn.Constructed != false {
					return fmt.Errorf("decoding nbrSN: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbrsn)
				}
				decVal_nbrsn, intErr := ber.DecodeIntegerValue(rawVal_nbrsn)
				if intErr != nil {
					return fmt.Errorf("decoding nbrSN: %w", intErr)
				}
				tmp_nbrsn := MCBearers4(decVal_nbrsn)
				v.NbrSN = &tmp_nbrsn
				offset += n_nbrsn
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "GenericServiceInfo4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERCCBSFeatureList4 encodes a CCBSFeatureList4 list to BER.
func MarshalBERCCBSFeatureList4(list CCBSFeatureList4) ([]byte, error) {
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

// UnmarshalBERCCBSFeatureList4 decodes a CCBSFeatureList4 list from BER.
func UnmarshalBERCCBSFeatureList4(data []byte) (CCBSFeatureList4, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding CCBSFeatureList4: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CCBSFeatureList4", Cause: ber.ErrExtraData}
	}
	var result CCBSFeatureList4
	offset := 0
	for offset < len(content) {
		var elem CCBSFeature4
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

// MarshalBER encodes CCBSFeature4 to BER format.
func (v *CCBSFeature4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CcbsIndex != nil {
		enc_ccbsindex := ber.EncodeInteger(int64(*v.CcbsIndex))
		enc_ccbsindex = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_ccbsindex)
		children = append(children, enc_ccbsindex...)
	}
	if v.BSubscriberNumber != nil {
		enc_bsubscribernumber := ber.EncodeOctetString([]byte(*v.BSubscriberNumber))
		enc_bsubscribernumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_bsubscribernumber)
		children = append(children, enc_bsubscribernumber...)
	}
	if v.BSubscriberSubaddress != nil {
		enc_bsubscribersubaddress := ber.EncodeOctetString([]byte(*v.BSubscriberSubaddress))
		enc_bsubscribersubaddress = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_bsubscribersubaddress)
		children = append(children, enc_bsubscribersubaddress...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroup: %w", err)
		}
		enc_basicservicegroup = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_basicservicegroup)
		children = append(children, enc_basicservicegroup...)
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

// MarshalDER encodes CCBSFeature4 to DER format.
func (v *CCBSFeature4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CCBSFeature4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CCBSFeature4 from BER/DER format.
func (v *CCBSFeature4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CCBSFeature4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CCBSFeature4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ccbs-Index
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_ccbsindex, n_ccbsindex, rawVal_ccbsindex, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Index: %w", err)
				}
				if decodedTag_ccbsindex.Class != tag.ClassContextSpecific || decodedTag_ccbsindex.Number != 0 || decodedTag_ccbsindex.Constructed != false {
					return fmt.Errorf("decoding ccbs-Index: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsindex)
				}
				decVal_ccbsindex, intErr := ber.DecodeIntegerValue(rawVal_ccbsindex)
				if intErr != nil {
					return fmt.Errorf("decoding ccbs-Index: %w", intErr)
				}
				tmp_ccbsindex := CCBSIndex4(decVal_ccbsindex)
				v.CcbsIndex = &tmp_ccbsindex
				offset += n_ccbsindex
			}
		}
	}
	// Decode b-subscriberNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_bsubscribernumber, n_bsubscribernumber, rawVal_bsubscribernumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding b-subscriberNumber: %w", err)
				}
				if decodedTag_bsubscribernumber.Class != tag.ClassContextSpecific || decodedTag_bsubscribernumber.Number != 1 {
					return fmt.Errorf("decoding b-subscriberNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bsubscribernumber)
				}
				tmp_bsubscribernumber := ISDNAddressString4(rawVal_bsubscribernumber)
				v.BSubscriberNumber = &tmp_bsubscribernumber
				offset += n_bsubscribernumber
			}
		}
	}
	// Decode b-subscriberSubaddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_bsubscribersubaddress, n_bsubscribersubaddress, rawVal_bsubscribersubaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding b-subscriberSubaddress: %w", err)
				}
				if decodedTag_bsubscribersubaddress.Class != tag.ClassContextSpecific || decodedTag_bsubscribersubaddress.Number != 2 {
					return fmt.Errorf("decoding b-subscriberSubaddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bsubscribersubaddress)
				}
				tmp_bsubscribersubaddress := ISDNSubaddressString4(rawVal_bsubscribersubaddress)
				v.BSubscriberSubaddress = &tmp_bsubscribersubaddress
				offset += n_bsubscribersubaddress
			}
		}
	}
	// Decode basicServiceGroup
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_basicservicegroup, n_basicservicegroup, innerData_basicservicegroup, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicServiceGroup: %w", err)
				}
				if decodedTag_basicservicegroup.Class != tag.ClassContextSpecific || decodedTag_basicservicegroup.Number != 3 || decodedTag_basicservicegroup.Constructed != true {
					return fmt.Errorf("decoding basicServiceGroup: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservicegroup)
				}
				// Decode inner value from explicit tag wrapper
				var dec_basicservicegroup BasicServiceCode4
				if unmErr := dec_basicservicegroup.UnmarshalBER(innerData_basicservicegroup); unmErr != nil {
					return fmt.Errorf("decoding basicServiceGroup: %w", unmErr)
				}
				v.BasicServiceGroup = &dec_basicservicegroup
				offset += n_basicservicegroup
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CCBSFeature4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes InterrogateSSRes4 to BER format.
func (v *InterrogateSSRes4) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case InterrogateSSRes4ChoiceSsStatus:
		if v.SsStatus == nil {
			return nil, fmt.Errorf("choice InterrogateSSRes4: ss-Status is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.SsStatus))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case InterrogateSSRes4ChoiceBasicServiceGroupList:
		enc_1, err := MarshalBERBasicServiceGroupList4(v.BasicServiceGroupList)
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_1)
		return enc_1, nil
	case InterrogateSSRes4ChoiceForwardingFeatureList:
		enc_2, err := MarshalBERForwardingFeatureList4(v.ForwardingFeatureList)
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingFeatureList: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	case InterrogateSSRes4ChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("choice InterrogateSSRes4: genericServiceInfo is nil")
		}
		enc_3, err := v.GenericServiceInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for InterrogateSSRes4", v.Choice)
	}
}

// MarshalDER encodes InterrogateSSRes4 to DER format.
func (v *InterrogateSSRes4) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case InterrogateSSRes4ChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("choice InterrogateSSRes4: genericServiceInfo is nil")
		}
		enc_der_3, err := v.GenericServiceInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_der_3)
		if derErr := ber.ValidateDERElement(enc_der_3); derErr != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo as DER: %w", derErr)
		}
		return enc_der_3, nil
	}
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding InterrogateSSRes4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes InterrogateSSRes4 from BER/DER format.
func (v *InterrogateSSRes4) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for InterrogateSSRes4 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InterrogateSSRes4: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding InterrogateSSRes4 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InterrogateSSRes4", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = InterrogateSSRes4ChoiceSsStatus
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ss-Status: %w", tlvErr)
		}
		tmp := SSStatus4(rawVal)
		v.SsStatus = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = InterrogateSSRes4ChoiceBasicServiceGroupList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding basicServiceGroupList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERBasicServiceGroupList4(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding basicServiceGroupList: %w", unmErr)
		}
		v.BasicServiceGroupList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = InterrogateSSRes4ChoiceForwardingFeatureList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding forwardingFeatureList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERForwardingFeatureList4(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding forwardingFeatureList: %w", unmErr)
		}
		v.ForwardingFeatureList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = InterrogateSSRes4ChoiceGenericServiceInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding genericServiceInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec GenericServiceInfo4
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding genericServiceInfo: %w", unmErr)
		}
		v.GenericServiceInfo = &dec
	} else {
		return fmt.Errorf("unknown tag %s for InterrogateSSRes4 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes USSDArg4 to BER format.
func (v *USSDArg4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	children = append(children, enc_ussddatacodingscheme...)
	enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	children = append(children, enc_ussdstring...)
	if v.AlertingPattern != nil {
		enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		children = append(children, enc_alertingpattern...)
	}
	if v.Msisdn != nil {
		enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_msisdn)
		children = append(children, enc_msisdn...)
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

// MarshalDER encodes USSDArg4 to DER format.
func (v *USSDArg4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding USSDArg4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes USSDArg4 from BER/DER format.
func (v *USSDArg4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding USSDArg4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "USSDArg4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ussd-DataCodingScheme
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-DataCodingScheme")
	}
	val_ussddatacodingscheme, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ussd-DataCodingScheme: %w", err)
	}
	v.UssdDataCodingScheme = USSDDataCodingScheme4(val_ussddatacodingscheme)
	offset += n
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	val_ussdstring, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ussd-String: %w", err)
	}
	v.UssdString = USSDString4(val_ussdstring)
	offset += n
	// Decode alertingPattern
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_alertingpattern, n, err := ber.DecodeOctetString(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding alertingPattern: %w", err)
				}
				tmp_alertingpattern := AlertingPattern4(val_alertingpattern)
				v.AlertingPattern = &tmp_alertingpattern
				offset += n
			}
		}
	}
	// Decode msisdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
					return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				tmp_msisdn := ISDNAddressString4(rawVal_msisdn)
				v.Msisdn = &tmp_msisdn
				offset += n_msisdn
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "USSDArg4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes USSDRes4 to BER format.
func (v *USSDRes4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	children = append(children, enc_ussddatacodingscheme...)
	enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	children = append(children, enc_ussdstring...)
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

// MarshalDER encodes USSDRes4 to DER format.
func (v *USSDRes4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding USSDRes4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes USSDRes4 from BER/DER format.
func (v *USSDRes4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding USSDRes4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "USSDRes4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ussd-DataCodingScheme
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-DataCodingScheme")
	}
	val_ussddatacodingscheme, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ussd-DataCodingScheme: %w", err)
	}
	v.UssdDataCodingScheme = USSDDataCodingScheme4(val_ussddatacodingscheme)
	offset += n
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	val_ussdstring, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ussd-String: %w", err)
	}
	v.UssdString = USSDString4(val_ussdstring)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "USSDRes4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSSList4 encodes a SSList4 list to BER.
func MarshalBERSSList4(list SSList4) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSSList4 decodes a SSList4 list from BER.
func UnmarshalBERSSList4(data []byte) (SSList4, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSList4: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSList4", Cause: ber.ErrExtraData}
	}
	var result SSList4
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, SSCode4(val))
		offset += n
	}
	return result, nil
}

// MarshalBERSSInfoList4 encodes a SSInfoList4 list to BER.
func MarshalBERSSInfoList4(list SSInfoList4) ([]byte, error) {
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

// UnmarshalBERSSInfoList4 decodes a SSInfoList4 list from BER.
func UnmarshalBERSSInfoList4(data []byte) (SSInfoList4, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSInfoList4: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSInfoList4", Cause: ber.ErrExtraData}
	}
	var result SSInfoList4
	offset := 0
	for offset < len(content) {
		var elem SSInfo4
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

// MarshalBERBasicServiceGroupList4 encodes a BasicServiceGroupList4 list to BER.
func MarshalBERBasicServiceGroupList4(list BasicServiceGroupList4) ([]byte, error) {
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

// UnmarshalBERBasicServiceGroupList4 decodes a BasicServiceGroupList4 list from BER.
func UnmarshalBERBasicServiceGroupList4(data []byte) (BasicServiceGroupList4, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding BasicServiceGroupList4: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BasicServiceGroupList4", Cause: ber.ErrExtraData}
	}
	var result BasicServiceGroupList4
	offset := 0
	for offset < len(content) {
		var elem BasicServiceCode4
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

// MarshalBER encodes SSInvocationNotificationArg4 to BER format.
func (v *SSInvocationNotificationArg4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	enc_imsi = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_imsi)
	children = append(children, enc_imsi...)
	enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	enc_msisdn = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_msisdn)
	children = append(children, enc_msisdn...)
	enc_ssevent := ber.EncodeOctetString([]byte(v.SsEvent))
	enc_ssevent = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_ssevent)
	children = append(children, enc_ssevent...)
	if v.SsEventSpecification != nil {
		enc_sseventspecification, err := MarshalBERSSEventSpecification4(v.SsEventSpecification)
		if err != nil {
			return nil, fmt.Errorf("encoding ss-EventSpecification: %w", err)
		}
		if v.SsEventSpecificationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_sseventspecification)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			enc_sseventspecification = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
		} else {
			enc_sseventspecification = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_sseventspecification)
		}
		children = append(children, enc_sseventspecification...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding extensionContainer: %w", err)
		}
		enc_extensioncontainer = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.BSubscriberNumber != nil {
		enc_bsubscribernumber := ber.EncodeOctetString([]byte(*v.BSubscriberNumber))
		enc_bsubscribernumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, false, enc_bsubscribernumber)
		children = append(children, enc_bsubscribernumber...)
	}
	if v.CcbsRequestState != nil {
		enc_ccbsrequeststate := ber.EncodeEnumerated(int64(*v.CcbsRequestState))
		enc_ccbsrequeststate = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, false, enc_ccbsrequeststate)
		children = append(children, enc_ccbsrequeststate...)
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

// MarshalDER encodes SSInvocationNotificationArg4 to DER format.
func (v *SSInvocationNotificationArg4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.SsEventSpecificationIndef_ = false
	v = &derValue
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSInvocationNotificationArg4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSInvocationNotificationArg4 from BER/DER format.
func (v *SSInvocationNotificationArg4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSInvocationNotificationArg4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInvocationNotificationArg4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset >= len(content) {
		return fmt.Errorf("missing required field imsi")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for imsi, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
		return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
	}
	v.Imsi = IMSI4(rawVal_imsi)
	offset += n_imsi
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("missing required field msisdn")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for msisdn, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 1 {
		return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
	}
	v.Msisdn = ISDNAddressString4(rawVal_msisdn)
	offset += n_msisdn
	// Decode ss-Event
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Event")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for ss-Event, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	decodedTag_ssevent, n_ssevent, rawVal_ssevent, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Event: %w", err)
	}
	if decodedTag_ssevent.Class != tag.ClassContextSpecific || decodedTag_ssevent.Number != 2 {
		return fmt.Errorf("decoding ss-Event: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssevent)
	}
	v.SsEvent = SSCode4(rawVal_ssevent)
	offset += n_ssevent
	// Decode ss-EventSpecification
	v.SsEventSpecificationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_sseventspecification, n_sseventspecification, rawVal_sseventspecification, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-EventSpecification: %w", err)
				}
				if decodedTag_sseventspecification.Class != tag.ClassContextSpecific || decodedTag_sseventspecification.Number != 3 || decodedTag_sseventspecification.Constructed != true {
					return fmt.Errorf("decoding ss-EventSpecification: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sseventspecification)
				}
				reconstructed_sseventspecification := ber.EncodeSequence(rawVal_sseventspecification)
				dec_sseventspecification, unmErr := UnmarshalBERSSEventSpecification4(reconstructed_sseventspecification)
				if unmErr != nil {
					return fmt.Errorf("decoding ss-EventSpecification: %w", unmErr)
				}
				v.SsEventSpecification = dec_sseventspecification
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.SsEventSpecificationIndef_ = true
					}
				}
				offset += n_sseventspecification
			}
		}
	}
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 || decodedTag_extensioncontainer.Constructed != true {
					return fmt.Errorf("decoding extensionContainer: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer4
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer); unmErr != nil {
					return fmt.Errorf("decoding extensionContainer: %w", unmErr)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				offset += n_extensioncontainer
			}
		}
	}
	// Decode b-subscriberNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_bsubscribernumber, n_bsubscribernumber, rawVal_bsubscribernumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding b-subscriberNumber: %w", err)
				}
				if decodedTag_bsubscribernumber.Class != tag.ClassContextSpecific || decodedTag_bsubscribernumber.Number != 5 {
					return fmt.Errorf("decoding b-subscriberNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bsubscribernumber)
				}
				tmp_bsubscribernumber := ISDNAddressString4(rawVal_bsubscribernumber)
				v.BSubscriberNumber = &tmp_bsubscribernumber
				offset += n_bsubscribernumber
			}
		}
	}
	// Decode ccbs-RequestState
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_ccbsrequeststate, n_ccbsrequeststate, rawVal_ccbsrequeststate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-RequestState: %w", err)
				}
				if decodedTag_ccbsrequeststate.Class != tag.ClassContextSpecific || decodedTag_ccbsrequeststate.Number != 6 || decodedTag_ccbsrequeststate.Constructed != false {
					return fmt.Errorf("decoding ccbs-RequestState: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsrequeststate)
				}
				decVal_ccbsrequeststate, intErr := ber.DecodeIntegerValue(rawVal_ccbsrequeststate)
				if intErr != nil {
					return fmt.Errorf("decoding ccbs-RequestState: %w", intErr)
				}
				tmp_ccbsrequeststate := CCBSRequestState4(decVal_ccbsrequeststate)
				v.CcbsRequestState = &tmp_ccbsrequeststate
				offset += n_ccbsrequeststate
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSInvocationNotificationArg4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSInvocationNotificationRes4 to BER format.
func (v *SSInvocationNotificationRes4) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSInvocationNotificationRes4 to DER format.
func (v *SSInvocationNotificationRes4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSInvocationNotificationRes4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSInvocationNotificationRes4 from BER/DER format.
func (v *SSInvocationNotificationRes4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSInvocationNotificationRes4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInvocationNotificationRes4", Cause: ber.ErrExtraData}
	}
	offset := 0
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSInvocationNotificationRes4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSSEventSpecification4 encodes a SSEventSpecification4 list to BER.
func MarshalBERSSEventSpecification4(list SSEventSpecification4) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSSEventSpecification4 decodes a SSEventSpecification4 list from BER.
func UnmarshalBERSSEventSpecification4(data []byte) (SSEventSpecification4, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSEventSpecification4: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSEventSpecification4", Cause: ber.ErrExtraData}
	}
	var result SSEventSpecification4
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, AddressString4(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes RegisterCCEntryArg4 to BER format.
func (v *RegisterCCEntryArg4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	enc_sscode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_sscode)
	children = append(children, enc_sscode...)
	if v.CcbsData != nil {
		enc_ccbsdata, err := v.CcbsData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-Data: %w", err)
		}
		enc_ccbsdata = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_ccbsdata)
		children = append(children, enc_ccbsdata...)
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

// MarshalDER encodes RegisterCCEntryArg4 to DER format.
func (v *RegisterCCEntryArg4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RegisterCCEntryArg4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RegisterCCEntryArg4 from BER/DER format.
func (v *RegisterCCEntryArg4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RegisterCCEntryArg4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterCCEntryArg4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ss-Code, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
		return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
	}
	v.SsCode = SSCode4(rawVal_sscode)
	offset += n_sscode
	// Decode ccbs-Data
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_ccbsdata, n_ccbsdata, rawVal_ccbsdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Data: %w", err)
				}
				if decodedTag_ccbsdata.Class != tag.ClassContextSpecific || decodedTag_ccbsdata.Number != 1 || decodedTag_ccbsdata.Constructed != true {
					return fmt.Errorf("decoding ccbs-Data: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsdata)
				}
				reconstructed_ccbsdata := ber.EncodeSequence(rawVal_ccbsdata)
				var dec_ccbsdata CCBSData4
				if unmErr := dec_ccbsdata.UnmarshalBER(reconstructed_ccbsdata); unmErr != nil {
					return fmt.Errorf("decoding ccbs-Data: %w", unmErr)
				}
				v.CcbsData = &dec_ccbsdata
				offset += n_ccbsdata
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterCCEntryArg4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CCBSData4 to BER format.
func (v *CCBSData4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_ccbsfeature, err := v.CcbsFeature.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding ccbs-Feature: %w", err)
	}
	enc_ccbsfeature = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_ccbsfeature)
	children = append(children, enc_ccbsfeature...)
	enc_translatedbnumber := ber.EncodeOctetString([]byte(v.TranslatedBNumber))
	enc_translatedbnumber = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_translatedbnumber)
	children = append(children, enc_translatedbnumber...)
	if v.ServiceIndicator != nil {
		enc_serviceindicator := ber.EncodeBitString(v.ServiceIndicator.Bytes, (8-(v.ServiceIndicator.BitLength%8))%8)
		enc_serviceindicator = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_serviceindicator)
		children = append(children, enc_serviceindicator...)
	}
	enc_callinfo, err := v.CallInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding callInfo: %w", err)
	}
	enc_callinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_callinfo)
	children = append(children, enc_callinfo...)
	enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER()
	if err != nil {
		return nil, fmt.Errorf("encoding networkSignalInfo: %w", err)
	}
	enc_networksignalinfo = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_networksignalinfo)
	children = append(children, enc_networksignalinfo...)
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

// MarshalDER encodes CCBSData4 to DER format.
func (v *CCBSData4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding CCBSData4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CCBSData4 from BER/DER format.
func (v *CCBSData4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CCBSData4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CCBSData4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ccbs-Feature
	if offset >= len(content) {
		return fmt.Errorf("missing required field ccbs-Feature")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ccbs-Feature, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_ccbsfeature, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ccbs-Feature: %w", err)
	}
	if decodedTag_ccbsfeature.Class != tag.ClassContextSpecific || decodedTag_ccbsfeature.Number != 0 || decodedTag_ccbsfeature.Constructed != true {
		return fmt.Errorf("decoding ccbs-Feature: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsfeature)
	}
	reconstructed_ccbsfeature := ber.EncodeSequence(rawVal_ccbsfeature)
	if unmErr := v.CcbsFeature.UnmarshalBER(reconstructed_ccbsfeature); unmErr != nil {
		return fmt.Errorf("decoding ccbs-Feature: %w", unmErr)
	}
	offset += n_ccbsfeature
	// Decode translatedB-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field translatedB-Number")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for translatedB-Number, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_translatedbnumber, n_translatedbnumber, rawVal_translatedbnumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding translatedB-Number: %w", err)
	}
	if decodedTag_translatedbnumber.Class != tag.ClassContextSpecific || decodedTag_translatedbnumber.Number != 1 {
		return fmt.Errorf("decoding translatedB-Number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_translatedbnumber)
	}
	v.TranslatedBNumber = ISDNAddressString4(rawVal_translatedbnumber)
	offset += n_translatedbnumber
	// Decode serviceIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_serviceindicator, n_serviceindicator, rawVal_serviceindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceIndicator: %w", err)
				}
				if decodedTag_serviceindicator.Class != tag.ClassContextSpecific || decodedTag_serviceindicator.Number != 2 {
					return fmt.Errorf("decoding serviceIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_serviceindicator)
				}
				bsBytes_serviceindicator, bsUnused_serviceindicator, bsErr := ber.DecodeBitStringValue(rawVal_serviceindicator)
				if bsErr != nil {
					return fmt.Errorf("decoding serviceIndicator: %w", bsErr)
				}
				tmp_serviceindicator := runtime.BitString{Bytes: bsBytes_serviceindicator, BitLength: len(bsBytes_serviceindicator)*8 - bsUnused_serviceindicator}
				v.ServiceIndicator = &tmp_serviceindicator
				offset += n_serviceindicator
			}
		}
	}
	// Decode callInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field callInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 3 {
			return fmt.Errorf("expected tag [%s %d] for callInfo, got %s", "CONTEXT", 3, reqTag_)
		}
	}
	decodedTag_callinfo, n_callinfo, rawVal_callinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding callInfo: %w", err)
	}
	if decodedTag_callinfo.Class != tag.ClassContextSpecific || decodedTag_callinfo.Number != 3 || decodedTag_callinfo.Constructed != true {
		return fmt.Errorf("decoding callInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callinfo)
	}
	reconstructed_callinfo := ber.EncodeSequence(rawVal_callinfo)
	if unmErr := v.CallInfo.UnmarshalBER(reconstructed_callinfo); unmErr != nil {
		return fmt.Errorf("decoding callInfo: %w", unmErr)
	}
	offset += n_callinfo
	// Decode networkSignalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field networkSignalInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for networkSignalInfo, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	decodedTag_networksignalinfo, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding networkSignalInfo: %w", err)
	}
	if decodedTag_networksignalinfo.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo.Number != 4 || decodedTag_networksignalinfo.Constructed != true {
		return fmt.Errorf("decoding networkSignalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo)
	}
	reconstructed_networksignalinfo := ber.EncodeSequence(rawVal_networksignalinfo)
	if unmErr := v.NetworkSignalInfo.UnmarshalBER(reconstructed_networksignalinfo); unmErr != nil {
		return fmt.Errorf("decoding networkSignalInfo: %w", unmErr)
	}
	offset += n_networksignalinfo
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CCBSData4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RegisterCCEntryRes4 to BER format.
func (v *RegisterCCEntryRes4) MarshalBER() ([]byte, error) {
	var children []byte
	if v.CcbsFeature != nil {
		enc_ccbsfeature, err := v.CcbsFeature.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-Feature: %w", err)
		}
		enc_ccbsfeature = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_ccbsfeature)
		children = append(children, enc_ccbsfeature...)
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

// MarshalDER encodes RegisterCCEntryRes4 to DER format.
func (v *RegisterCCEntryRes4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding RegisterCCEntryRes4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RegisterCCEntryRes4 from BER/DER format.
func (v *RegisterCCEntryRes4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RegisterCCEntryRes4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterCCEntryRes4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ccbs-Feature
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_ccbsfeature, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Feature: %w", err)
				}
				if decodedTag_ccbsfeature.Class != tag.ClassContextSpecific || decodedTag_ccbsfeature.Number != 0 || decodedTag_ccbsfeature.Constructed != true {
					return fmt.Errorf("decoding ccbs-Feature: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsfeature)
				}
				reconstructed_ccbsfeature := ber.EncodeSequence(rawVal_ccbsfeature)
				var dec_ccbsfeature CCBSFeature4
				if unmErr := dec_ccbsfeature.UnmarshalBER(reconstructed_ccbsfeature); unmErr != nil {
					return fmt.Errorf("decoding ccbs-Feature: %w", unmErr)
				}
				v.CcbsFeature = &dec_ccbsfeature
				offset += n_ccbsfeature
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterCCEntryRes4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EraseCCEntryArg4 to BER format.
func (v *EraseCCEntryArg4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	enc_sscode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_sscode)
	children = append(children, enc_sscode...)
	if v.CcbsIndex != nil {
		enc_ccbsindex := ber.EncodeInteger(int64(*v.CcbsIndex))
		enc_ccbsindex = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_ccbsindex)
		children = append(children, enc_ccbsindex...)
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

// MarshalDER encodes EraseCCEntryArg4 to DER format.
func (v *EraseCCEntryArg4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding EraseCCEntryArg4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EraseCCEntryArg4 from BER/DER format.
func (v *EraseCCEntryArg4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EraseCCEntryArg4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EraseCCEntryArg4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ss-Code, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
		return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
	}
	v.SsCode = SSCode4(rawVal_sscode)
	offset += n_sscode
	// Decode ccbs-Index
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_ccbsindex, n_ccbsindex, rawVal_ccbsindex, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Index: %w", err)
				}
				if decodedTag_ccbsindex.Class != tag.ClassContextSpecific || decodedTag_ccbsindex.Number != 1 || decodedTag_ccbsindex.Constructed != false {
					return fmt.Errorf("decoding ccbs-Index: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsindex)
				}
				decVal_ccbsindex, intErr := ber.DecodeIntegerValue(rawVal_ccbsindex)
				if intErr != nil {
					return fmt.Errorf("decoding ccbs-Index: %w", intErr)
				}
				tmp_ccbsindex := CCBSIndex4(decVal_ccbsindex)
				v.CcbsIndex = &tmp_ccbsindex
				offset += n_ccbsindex
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EraseCCEntryArg4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EraseCCEntryRes4 to BER format.
func (v *EraseCCEntryRes4) MarshalBER() ([]byte, error) {
	var children []byte
	enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	enc_sscode = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_sscode)
	children = append(children, enc_sscode...)
	if v.SsStatus != nil {
		enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		enc_ssstatus = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_ssstatus)
		children = append(children, enc_ssstatus...)
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

// MarshalDER encodes EraseCCEntryRes4 to DER format.
func (v *EraseCCEntryRes4) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding EraseCCEntryRes4 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EraseCCEntryRes4 from BER/DER format.
func (v *EraseCCEntryRes4) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EraseCCEntryRes4 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EraseCCEntryRes4", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("expected tag [%s %d] for ss-Code, got %s", "CONTEXT", 0, reqTag_)
		}
	}
	decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
		return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
	}
	v.SsCode = SSCode4(rawVal_sscode)
	offset += n_sscode
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 1 {
					return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
				}
				tmp_ssstatus := SSStatus4(rawVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				offset += n_ssstatus
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "EraseCCEntryRes4", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
