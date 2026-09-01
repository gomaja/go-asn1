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

	// MaxNumOfCCBSRequests5 is the integer constant for MaxNumOfCCBSRequests5.
	MaxNumOfCCBSRequests5 int64 = 5

	// MaxUSSDStringLength5 is the integer constant for MaxUSSDStringLength5.
	MaxUSSDStringLength5 int64 = 160

	// MaxNumOfSS5 is the integer constant for MaxNumOfSS5.
	MaxNumOfSS5 int64 = 30

	// MaxNumOfBasicServiceGroups5 is the integer constant for MaxNumOfBasicServiceGroups5.
	MaxNumOfBasicServiceGroups5 int64 = 13

	// MaxEventSpecification5 is the integer constant for MaxEventSpecification5.
	MaxEventSpecification5 int64 = 2
)

// RegisterSSArg5 represents the ASN.1 type RegisterSSArg5 (SEQUENCE).
type RegisterSSArg5 struct {
	SsCode                SSCode5                `asn1:""`
	BasicService          *BasicServiceCode5     `asn1:",optional" json:"BasicService,omitempty"`
	ForwardedToNumber     *AddressString5        `asn1:"tag:4,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString5 `asn1:"tag:6,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	NoReplyConditionTime  *NoReplyConditionTime5 `asn1:"tag:5,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	DefaultPriority       *EMLPPPriority5        `asn1:"tag:7,context,implicit,optional" json:"DefaultPriority,omitempty"`
	NbrUser               *MCBearers5            `asn1:"tag:8,context,implicit,optional" json:"NbrUser,omitempty"`
	LongFTNSupported      *struct{}              `asn1:"tag:9,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
}

// NoReplyConditionTime5 represents the ASN.1 type NoReplyConditionTime5 (INTEGER).
type NoReplyConditionTime5 = int64

// SSInfo5 choice constants.
const (
	SSInfo5ChoiceForwardingInfo  = 1
	SSInfo5ChoiceCallBarringInfo = 2
	SSInfo5ChoiceSsData          = 3
)

// SSInfo5 represents the ASN.1 CHOICE type SSInfo5.
type SSInfo5 struct {
	Choice          int
	ForwardingInfo  *ForwardingInfo5  `json:"ForwardingInfo,omitempty"`
	CallBarringInfo *CallBarringInfo5 `json:"CallBarringInfo,omitempty"`
	SsData          *SSData5          `json:"SsData,omitempty"`
}

// NewSSInfo5ForwardingInfo creates a SSInfo5 with the forwardingInfo alternative.
func NewSSInfo5ForwardingInfo(v ForwardingInfo5) SSInfo5 {
	return SSInfo5{
		Choice:         SSInfo5ChoiceForwardingInfo,
		ForwardingInfo: &v,
	}
}

// NewSSInfo5CallBarringInfo creates a SSInfo5 with the callBarringInfo alternative.
func NewSSInfo5CallBarringInfo(v CallBarringInfo5) SSInfo5 {
	return SSInfo5{
		Choice:          SSInfo5ChoiceCallBarringInfo,
		CallBarringInfo: &v,
	}
}

// NewSSInfo5SsData creates a SSInfo5 with the ss-Data alternative.
func NewSSInfo5SsData(v SSData5) SSInfo5 {
	return SSInfo5{
		Choice: SSInfo5ChoiceSsData,
		SsData: &v,
	}
}

// ForwardingInfo5 represents the ASN.1 type ForwardingInfo5 (SEQUENCE).
type ForwardingInfo5 struct {
	SsCode                      *SSCode5               `asn1:",optional" json:"SsCode,omitempty"`
	ForwardingFeatureList       ForwardingFeatureList5 `asn1:""`
	ForwardingFeatureListIndef_ bool                   `asn1:"-" json:"-"`
	ExtCount_                   int64                  `asn1:"-" json:"-"`
	ExtPresent_                 []bool                 `asn1:"-" json:"-"`
	ExtData_                    [][]byte               `asn1:"-" json:"-"`
}

// ForwardingFeatureList5 represents the ASN.1 type ForwardingFeatureList5 (SEQUENCE_OF).
type ForwardingFeatureList5 = []ForwardingFeature5

// ForwardingFeature5 represents the ASN.1 type ForwardingFeature5 (SEQUENCE).
type ForwardingFeature5 struct {
	BasicService          *BasicServiceCode5     `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus              *SSStatus5             `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ForwardedToNumber     *ISDNAddressString5    `asn1:"tag:5,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString5 `asn1:"tag:8,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	ForwardingOptions     *ForwardingOptions5    `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	NoReplyConditionTime  *NoReplyConditionTime5 `asn1:"tag:7,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	LongForwardedToNumber *FTNAddressString5     `asn1:"tag:9,context,implicit,optional" json:"LongForwardedToNumber,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
}

// SSStatus5 represents the ASN.1 type SSStatus5 (OCTET_STRING).
type SSStatus5 = []byte

// ForwardingOptions5 represents the ASN.1 type ForwardingOptions5 (OCTET_STRING).
type ForwardingOptions5 = []byte

// CallBarringInfo5 represents the ASN.1 type CallBarringInfo5 (SEQUENCE).
type CallBarringInfo5 struct {
	SsCode                       *SSCode5                `asn1:",optional" json:"SsCode,omitempty"`
	CallBarringFeatureList       CallBarringFeatureList5 `asn1:""`
	CallBarringFeatureListIndef_ bool                    `asn1:"-" json:"-"`
	ExtCount_                    int64                   `asn1:"-" json:"-"`
	ExtPresent_                  []bool                  `asn1:"-" json:"-"`
	ExtData_                     [][]byte                `asn1:"-" json:"-"`
}

// CallBarringFeatureList5 represents the ASN.1 type CallBarringFeatureList5 (SEQUENCE_OF).
type CallBarringFeatureList5 = []CallBarringFeature5

// CallBarringFeature5 represents the ASN.1 type CallBarringFeature5 (SEQUENCE).
type CallBarringFeature5 struct {
	BasicService *BasicServiceCode5 `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSStatus5         `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64              `asn1:"-" json:"-"`
	ExtPresent_  []bool             `asn1:"-" json:"-"`
	ExtData_     [][]byte           `asn1:"-" json:"-"`
}

// SSData5 represents the ASN.1 type SSData5 (SEQUENCE).
type SSData5 struct {
	SsCode                      *SSCode5               `asn1:",optional" json:"SsCode,omitempty"`
	SsStatus                    *SSStatus5             `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	SsSubscriptionOption        *SSSubscriptionOption5 `asn1:",optional" json:"SsSubscriptionOption,omitempty"`
	BasicServiceGroupList       BasicServiceGroupList5 `asn1:",optional" json:"BasicServiceGroupList,omitempty"`
	BasicServiceGroupListIndef_ bool                   `asn1:"-" json:"-"`
	DefaultPriority             *EMLPPPriority5        `asn1:",optional" json:"DefaultPriority,omitempty"`
	NbrUser                     *MCBearers5            `asn1:"tag:5,context,implicit,optional" json:"NbrUser,omitempty"`
	ExtCount_                   int64                  `asn1:"-" json:"-"`
	ExtPresent_                 []bool                 `asn1:"-" json:"-"`
	ExtData_                    [][]byte               `asn1:"-" json:"-"`
}

// SSSubscriptionOption5 choice constants.
const (
	SSSubscriptionOption5ChoiceCliRestrictionOption = 1
	SSSubscriptionOption5ChoiceOverrideCategory     = 2
)

// SSSubscriptionOption5 represents the ASN.1 CHOICE type SSSubscriptionOption5.
type SSSubscriptionOption5 struct {
	Choice               int
	CliRestrictionOption *CliRestrictionOption5 `json:"CliRestrictionOption,omitempty"`
	OverrideCategory     *OverrideCategory5     `json:"OverrideCategory,omitempty"`
}

// NewSSSubscriptionOption5CliRestrictionOption creates a SSSubscriptionOption5 with the cliRestrictionOption alternative.
func NewSSSubscriptionOption5CliRestrictionOption(v CliRestrictionOption5) SSSubscriptionOption5 {
	return SSSubscriptionOption5{
		Choice:               SSSubscriptionOption5ChoiceCliRestrictionOption,
		CliRestrictionOption: &v,
	}
}

// NewSSSubscriptionOption5OverrideCategory creates a SSSubscriptionOption5 with the overrideCategory alternative.
func NewSSSubscriptionOption5OverrideCategory(v OverrideCategory5) SSSubscriptionOption5 {
	return SSSubscriptionOption5{
		Choice:           SSSubscriptionOption5ChoiceOverrideCategory,
		OverrideCategory: &v,
	}
}

// CliRestrictionOption5 represents the ASN.1 ENUMERATED type CliRestrictionOption5.
type CliRestrictionOption5 int64

const (
	CliRestrictionOption5Permanent                  CliRestrictionOption5 = 0
	CliRestrictionOption5TemporaryDefaultRestricted CliRestrictionOption5 = 1
	CliRestrictionOption5TemporaryDefaultAllowed    CliRestrictionOption5 = 2
)

func (v CliRestrictionOption5) String() string {
	switch v {
	case CliRestrictionOption5Permanent:
		return "permanent"
	case CliRestrictionOption5TemporaryDefaultRestricted:
		return "temporaryDefaultRestricted"
	case CliRestrictionOption5TemporaryDefaultAllowed:
		return "temporaryDefaultAllowed"
	default:
		return "unknown"
	}
}

// OverrideCategory5 represents the ASN.1 ENUMERATED type OverrideCategory5.
type OverrideCategory5 int64

const (
	OverrideCategory5OverrideEnabled  OverrideCategory5 = 0
	OverrideCategory5OverrideDisabled OverrideCategory5 = 1
)

func (v OverrideCategory5) String() string {
	switch v {
	case OverrideCategory5OverrideEnabled:
		return "overrideEnabled"
	case OverrideCategory5OverrideDisabled:
		return "overrideDisabled"
	default:
		return "unknown"
	}
}

// SSForBSCode5 represents the ASN.1 type SSForBSCode5 (SEQUENCE).
type SSForBSCode5 struct {
	SsCode           SSCode5            `asn1:""`
	BasicService     *BasicServiceCode5 `asn1:",optional" json:"BasicService,omitempty"`
	LongFTNSupported *struct{}          `asn1:"tag:4,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_        int64              `asn1:"-" json:"-"`
	ExtPresent_      []bool             `asn1:"-" json:"-"`
	ExtData_         [][]byte           `asn1:"-" json:"-"`
}

// GenericServiceInfo5 represents the ASN.1 type GenericServiceInfo5 (SEQUENCE).
type GenericServiceInfo5 struct {
	SsStatus                SSStatus5              `asn1:""`
	CliRestrictionOption    *CliRestrictionOption5 `asn1:",optional" json:"CliRestrictionOption,omitempty"`
	MaximumEntitledPriority *EMLPPPriority5        `asn1:"tag:0,context,implicit,optional" json:"MaximumEntitledPriority,omitempty"`
	DefaultPriority         *EMLPPPriority5        `asn1:"tag:1,context,implicit,optional" json:"DefaultPriority,omitempty"`
	CcbsFeatureList         CCBSFeatureList5       `asn1:"tag:2,context,implicit,optional" json:"CcbsFeatureList,omitempty"`
	CcbsFeatureListIndef_   bool                   `asn1:"-" json:"-"`
	NbrSB                   *MaxMCBearers5         `asn1:"tag:3,context,implicit,optional" json:"NbrSB,omitempty"`
	NbrUser                 *MCBearers5            `asn1:"tag:4,context,implicit,optional" json:"NbrUser,omitempty"`
	NbrSN                   *MCBearers5            `asn1:"tag:5,context,implicit,optional" json:"NbrSN,omitempty"`
	ExtCount_               int64                  `asn1:"-" json:"-"`
	ExtPresent_             []bool                 `asn1:"-" json:"-"`
	ExtData_                [][]byte               `asn1:"-" json:"-"`
}

// CCBSFeatureList5 represents the ASN.1 type CCBSFeatureList5 (SEQUENCE_OF).
type CCBSFeatureList5 = []CCBSFeature5

// CCBSFeature5 represents the ASN.1 type CCBSFeature5 (SEQUENCE).
type CCBSFeature5 struct {
	CcbsIndex             *CCBSIndex5            `asn1:"tag:0,context,implicit,optional" json:"CcbsIndex,omitempty"`
	BSubscriberNumber     *ISDNAddressString5    `asn1:"tag:1,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	BSubscriberSubaddress *ISDNSubaddressString5 `asn1:"tag:2,context,implicit,optional" json:"BSubscriberSubaddress,omitempty"`
	BasicServiceGroup     *BasicServiceCode5     `asn1:"tag:3,context,explicit,optional" json:"BasicServiceGroup,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
}

// CCBSIndex5 represents the ASN.1 type CCBSIndex5 (INTEGER).
type CCBSIndex5 = int64

// InterrogateSSRes5 choice constants.
const (
	InterrogateSSRes5ChoiceSsStatus              = 1
	InterrogateSSRes5ChoiceBasicServiceGroupList = 2
	InterrogateSSRes5ChoiceForwardingFeatureList = 3
	InterrogateSSRes5ChoiceGenericServiceInfo    = 4
)

// InterrogateSSRes5 represents the ASN.1 CHOICE type InterrogateSSRes5.
type InterrogateSSRes5 struct {
	Choice                int
	SsStatus              *SSStatus5             `json:"SsStatus,omitempty"`
	BasicServiceGroupList BasicServiceGroupList5 `json:"BasicServiceGroupList,omitempty"`
	ForwardingFeatureList ForwardingFeatureList5 `json:"ForwardingFeatureList,omitempty"`
	GenericServiceInfo    *GenericServiceInfo5   `json:"GenericServiceInfo,omitempty"`
}

// NewInterrogateSSRes5SsStatus creates a InterrogateSSRes5 with the ss-Status alternative.
func NewInterrogateSSRes5SsStatus(v SSStatus5) InterrogateSSRes5 {
	return InterrogateSSRes5{
		Choice:   InterrogateSSRes5ChoiceSsStatus,
		SsStatus: &v,
	}
}

// NewInterrogateSSRes5BasicServiceGroupList creates a InterrogateSSRes5 with the basicServiceGroupList alternative.
func NewInterrogateSSRes5BasicServiceGroupList(v BasicServiceGroupList5) InterrogateSSRes5 {
	return InterrogateSSRes5{
		Choice:                InterrogateSSRes5ChoiceBasicServiceGroupList,
		BasicServiceGroupList: v,
	}
}

// NewInterrogateSSRes5ForwardingFeatureList creates a InterrogateSSRes5 with the forwardingFeatureList alternative.
func NewInterrogateSSRes5ForwardingFeatureList(v ForwardingFeatureList5) InterrogateSSRes5 {
	return InterrogateSSRes5{
		Choice:                InterrogateSSRes5ChoiceForwardingFeatureList,
		ForwardingFeatureList: v,
	}
}

// NewInterrogateSSRes5GenericServiceInfo creates a InterrogateSSRes5 with the genericServiceInfo alternative.
func NewInterrogateSSRes5GenericServiceInfo(v GenericServiceInfo5) InterrogateSSRes5 {
	return InterrogateSSRes5{
		Choice:             InterrogateSSRes5ChoiceGenericServiceInfo,
		GenericServiceInfo: &v,
	}
}

// USSDArg5 represents the ASN.1 type USSDArg5 (SEQUENCE).
type USSDArg5 struct {
	UssdDataCodingScheme USSDDataCodingScheme5 `asn1:""`
	UssdString           USSDString5           `asn1:""`
	AlertingPattern      *AlertingPattern5     `asn1:",optional" json:"AlertingPattern,omitempty"`
	Msisdn               *ISDNAddressString5   `asn1:"tag:0,context,implicit,optional" json:"Msisdn,omitempty"`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	ExtData_             [][]byte              `asn1:"-" json:"-"`
}

// USSDRes5 represents the ASN.1 type USSDRes5 (SEQUENCE).
type USSDRes5 struct {
	UssdDataCodingScheme USSDDataCodingScheme5 `asn1:""`
	UssdString           USSDString5           `asn1:""`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	ExtData_             [][]byte              `asn1:"-" json:"-"`
}

// USSDDataCodingScheme5 represents the ASN.1 type USSDDataCodingScheme5 (OCTET_STRING).
type USSDDataCodingScheme5 = []byte

// USSDString5 represents the ASN.1 type USSDString5 (OCTET_STRING).
type USSDString5 = []byte

// Password5 represents the ASN.1 type Password5 (NumericString).
type Password5 = string

// GuidanceInfo5 represents the ASN.1 ENUMERATED type GuidanceInfo5.
type GuidanceInfo5 int64

const (
	GuidanceInfo5EnterPW         GuidanceInfo5 = 0
	GuidanceInfo5EnterNewPW      GuidanceInfo5 = 1
	GuidanceInfo5EnterNewPWAgain GuidanceInfo5 = 2
)

func (v GuidanceInfo5) String() string {
	switch v {
	case GuidanceInfo5EnterPW:
		return "enterPW"
	case GuidanceInfo5EnterNewPW:
		return "enterNewPW"
	case GuidanceInfo5EnterNewPWAgain:
		return "enterNewPW-Again"
	default:
		return "unknown"
	}
}

// SSList5 represents the ASN.1 type SSList5 (SEQUENCE_OF).
type SSList5 = []SSCode5

// SSInfoList5 represents the ASN.1 type SSInfoList5 (SEQUENCE_OF).
type SSInfoList5 = []SSInfo5

// BasicServiceGroupList5 represents the ASN.1 type BasicServiceGroupList5 (SEQUENCE_OF).
type BasicServiceGroupList5 = []BasicServiceCode5

// SSInvocationNotificationArg5 represents the ASN.1 type SSInvocationNotificationArg5 (SEQUENCE).
type SSInvocationNotificationArg5 struct {
	Imsi                       IMSI5                 `asn1:"tag:0,context,implicit"`
	Msisdn                     ISDNAddressString5    `asn1:"tag:1,context,implicit"`
	SsEvent                    SSCode5               `asn1:"tag:2,context,implicit"`
	SsEventSpecification       SSEventSpecification5 `asn1:"tag:3,context,implicit,optional" json:"SsEventSpecification,omitempty"`
	SsEventSpecificationIndef_ bool                  `asn1:"-" json:"-"`
	ExtensionContainer         *ExtensionContainer5  `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	BSubscriberNumber          *ISDNAddressString5   `asn1:"tag:5,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	CcbsRequestState           *CCBSRequestState5    `asn1:"tag:6,context,implicit,optional" json:"CcbsRequestState,omitempty"`
	ExtCount_                  int64                 `asn1:"-" json:"-"`
	ExtPresent_                []bool                `asn1:"-" json:"-"`
	ExtData_                   [][]byte              `asn1:"-" json:"-"`
}

// CCBSRequestState5 represents the ASN.1 ENUMERATED type CCBSRequestState5.
type CCBSRequestState5 int64

const (
	CCBSRequestState5Request   CCBSRequestState5 = 0
	CCBSRequestState5Recall    CCBSRequestState5 = 1
	CCBSRequestState5Active    CCBSRequestState5 = 2
	CCBSRequestState5Completed CCBSRequestState5 = 3
	CCBSRequestState5Suspended CCBSRequestState5 = 4
	CCBSRequestState5Frozen    CCBSRequestState5 = 5
	CCBSRequestState5Deleted   CCBSRequestState5 = 6
)

func (v CCBSRequestState5) String() string {
	switch v {
	case CCBSRequestState5Request:
		return "request"
	case CCBSRequestState5Recall:
		return "recall"
	case CCBSRequestState5Active:
		return "active"
	case CCBSRequestState5Completed:
		return "completed"
	case CCBSRequestState5Suspended:
		return "suspended"
	case CCBSRequestState5Frozen:
		return "frozen"
	case CCBSRequestState5Deleted:
		return "deleted"
	default:
		return "unknown"
	}
}

// SSInvocationNotificationRes5 represents the ASN.1 type SSInvocationNotificationRes5 (SEQUENCE).
type SSInvocationNotificationRes5 struct {
	ExtensionContainer *ExtensionContainer5 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SSEventSpecification5 represents the ASN.1 type SSEventSpecification5 (SEQUENCE_OF).
type SSEventSpecification5 = []AddressString5

// RegisterCCEntryArg5 represents the ASN.1 type RegisterCCEntryArg5 (SEQUENCE).
type RegisterCCEntryArg5 struct {
	SsCode      SSCode5    `asn1:"tag:0,context,implicit"`
	CcbsData    *CCBSData5 `asn1:"tag:1,context,implicit,optional" json:"CcbsData,omitempty"`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	ExtData_    [][]byte   `asn1:"-" json:"-"`
}

// CCBSData5 represents the ASN.1 type CCBSData5 (SEQUENCE).
type CCBSData5 struct {
	CcbsFeature       CCBSFeature5        `asn1:"tag:0,context,implicit"`
	TranslatedBNumber ISDNAddressString5  `asn1:"tag:1,context,implicit"`
	ServiceIndicator  *ServiceIndicator5  `asn1:"tag:2,context,implicit,optional" json:"ServiceIndicator,omitempty"`
	CallInfo          ExternalSignalInfo5 `asn1:"tag:3,context,implicit"`
	NetworkSignalInfo ExternalSignalInfo5 `asn1:"tag:4,context,implicit"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ServiceIndicator5 represents the ASN.1 type ServiceIndicator5 (BIT_STRING).
type ServiceIndicator5 = runtime.BitString

// RegisterCCEntryRes5 represents the ASN.1 type RegisterCCEntryRes5 (SEQUENCE).
type RegisterCCEntryRes5 struct {
	CcbsFeature *CCBSFeature5 `asn1:"tag:0,context,implicit,optional" json:"CcbsFeature,omitempty"`
	ExtCount_   int64         `asn1:"-" json:"-"`
	ExtPresent_ []bool        `asn1:"-" json:"-"`
	ExtData_    [][]byte      `asn1:"-" json:"-"`
}

// EraseCCEntryArg5 represents the ASN.1 type EraseCCEntryArg5 (SEQUENCE).
type EraseCCEntryArg5 struct {
	SsCode      SSCode5     `asn1:"tag:0,context,implicit"`
	CcbsIndex   *CCBSIndex5 `asn1:"tag:1,context,implicit,optional" json:"CcbsIndex,omitempty"`
	ExtCount_   int64       `asn1:"-" json:"-"`
	ExtPresent_ []bool      `asn1:"-" json:"-"`
	ExtData_    [][]byte    `asn1:"-" json:"-"`
}

// EraseCCEntryRes5 represents the ASN.1 type EraseCCEntryRes5 (SEQUENCE).
type EraseCCEntryRes5 struct {
	SsCode      SSCode5    `asn1:"tag:0,context,implicit"`
	SsStatus    *SSStatus5 `asn1:"tag:1,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	ExtData_    [][]byte   `asn1:"-" json:"-"`
}

// MarshalBER encodes RegisterSSArg5 to BER format.
func (v *RegisterSSArg5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes RegisterSSArg5 to DER format.
func (v *RegisterSSArg5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RegisterSSArg5 from BER/DER format.
func (v *RegisterSSArg5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RegisterSSArg5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterSSArg5", Cause: ber.ErrExtraData}
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
	v.SsCode = SSCode5(val_sscode)
	offset += n
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode5)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode5
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
				_, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToNumber: %w", err)
				}
				tmp_forwardedtonumber := AddressString5(rawVal_forwardedtonumber)
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
				_, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToSubaddress: %w", err)
				}
				tmp_forwardedtosubaddress := ISDNSubaddressString5(rawVal_forwardedtosubaddress)
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
				_, n_noreplyconditiontime, rawVal_noreplyconditiontime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding noReplyConditionTime: %w", err)
				}
				decVal_noreplyconditiontime, intErr := ber.DecodeIntegerValue(rawVal_noreplyconditiontime)
				if intErr != nil {
					return fmt.Errorf("decoding noReplyConditionTime: %w", intErr)
				}
				tmp_noreplyconditiontime := NoReplyConditionTime5(decVal_noreplyconditiontime)
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
				_, n_defaultpriority, rawVal_defaultpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding defaultPriority: %w", err)
				}
				decVal_defaultpriority, intErr := ber.DecodeIntegerValue(rawVal_defaultpriority)
				if intErr != nil {
					return fmt.Errorf("decoding defaultPriority: %w", intErr)
				}
				tmp_defaultpriority := EMLPPPriority5(decVal_defaultpriority)
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
				_, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nbrUser: %w", err)
				}
				decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
				if intErr != nil {
					return fmt.Errorf("decoding nbrUser: %w", intErr)
				}
				tmp_nbruser := MCBearers5(decVal_nbruser)
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
				_, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longFTN-Supported: %w", err)
				}
				_ = rawVal_longftnsupported
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
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterSSArg5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSInfo5 to BER format.
func (v *SSInfo5) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SSInfo5ChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("choice SSInfo5: forwardingInfo is nil")
		}
		enc_0, err := v.ForwardingInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingInfo: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case SSInfo5ChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("choice SSInfo5: callBarringInfo is nil")
		}
		enc_1, err := v.CallBarringInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding callBarringInfo: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		return enc_1, nil
	case SSInfo5ChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("choice SSInfo5: ss-Data is nil")
		}
		enc_2, err := v.SsData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ss-Data: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSInfo5", v.Choice)
	}
}

// MarshalDER encodes SSInfo5 to DER format.
func (v *SSInfo5) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case SSInfo5ChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("choice SSInfo5: forwardingInfo is nil")
		}
		enc_der_0, err := v.ForwardingInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingInfo: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		return enc_der_0, nil
	case SSInfo5ChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("choice SSInfo5: callBarringInfo is nil")
		}
		enc_der_1, err := v.CallBarringInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding callBarringInfo: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		return enc_der_1, nil
	case SSInfo5ChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("choice SSInfo5: ss-Data is nil")
		}
		enc_der_2, err := v.SsData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ss-Data: %w", err)
		}
		enc_der_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_der_2)
		return enc_der_2, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes SSInfo5 from BER/DER format.
func (v *SSInfo5) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSInfo5 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSInfo5: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SSInfo5 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInfo5", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SSInfo5ChoiceForwardingInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding forwardingInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ForwardingInfo5
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding forwardingInfo: %w", unmErr)
		}
		v.ForwardingInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SSInfo5ChoiceCallBarringInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding callBarringInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CallBarringInfo5
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding callBarringInfo: %w", unmErr)
		}
		v.CallBarringInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = SSInfo5ChoiceSsData
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ss-Data: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SSData5
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding ss-Data: %w", unmErr)
		}
		v.SsData = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SSInfo5 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ForwardingInfo5 to BER format.
func (v *ForwardingInfo5) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		children = append(children, enc_sscode...)
	}
	enc_forwardingfeaturelist, err := MarshalBERForwardingFeatureList5(v.ForwardingFeatureList)
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

// MarshalDER encodes ForwardingInfo5 to DER format.
func (v *ForwardingInfo5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.ForwardingFeatureListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes ForwardingInfo5 from BER/DER format.
func (v *ForwardingInfo5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardingInfo5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingInfo5", Cause: ber.ErrExtraData}
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
				tmp_sscode := SSCode5(val_sscode)
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
	// Decode nested SEQUENCE_OF (ForwardingFeatureList5)
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
	dec_forwardingfeaturelist, unmErr := UnmarshalBERForwardingFeatureList5(tlv_forwardingfeaturelist)
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingInfo5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERForwardingFeatureList5 encodes a ForwardingFeatureList5 list to BER.
func MarshalBERForwardingFeatureList5(list ForwardingFeatureList5) ([]byte, error) {
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

// UnmarshalBERForwardingFeatureList5 decodes a ForwardingFeatureList5 list from BER.
func UnmarshalBERForwardingFeatureList5(data []byte) (ForwardingFeatureList5, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ForwardingFeatureList5: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ForwardingFeatureList5", Cause: ber.ErrExtraData}
	}
	var result ForwardingFeatureList5
	offset := 0
	for offset < len(content) {
		var elem ForwardingFeature5
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

// MarshalBER encodes ForwardingFeature5 to BER format.
func (v *ForwardingFeature5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ForwardingFeature5 to DER format.
func (v *ForwardingFeature5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes ForwardingFeature5 from BER/DER format.
func (v *ForwardingFeature5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardingFeature5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingFeature5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode5)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode5
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
				_, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				tmp_ssstatus := SSStatus5(rawVal_ssstatus)
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
				_, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToNumber: %w", err)
				}
				tmp_forwardedtonumber := ISDNAddressString5(rawVal_forwardedtonumber)
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
				_, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardedToSubaddress: %w", err)
				}
				tmp_forwardedtosubaddress := ISDNSubaddressString5(rawVal_forwardedtosubaddress)
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
				_, n_forwardingoptions, rawVal_forwardingoptions, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding forwardingOptions: %w", err)
				}
				tmp_forwardingoptions := ForwardingOptions5(rawVal_forwardingoptions)
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
				_, n_noreplyconditiontime, rawVal_noreplyconditiontime, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding noReplyConditionTime: %w", err)
				}
				decVal_noreplyconditiontime, intErr := ber.DecodeIntegerValue(rawVal_noreplyconditiontime)
				if intErr != nil {
					return fmt.Errorf("decoding noReplyConditionTime: %w", intErr)
				}
				tmp_noreplyconditiontime := NoReplyConditionTime5(decVal_noreplyconditiontime)
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
				_, n_longforwardedtonumber, rawVal_longforwardedtonumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longForwardedToNumber: %w", err)
				}
				tmp_longforwardedtonumber := FTNAddressString5(rawVal_longforwardedtonumber)
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingFeature5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CallBarringInfo5 to BER format.
func (v *CallBarringInfo5) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		children = append(children, enc_sscode...)
	}
	enc_callbarringfeaturelist, err := MarshalBERCallBarringFeatureList5(v.CallBarringFeatureList)
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

// MarshalDER encodes CallBarringInfo5 to DER format.
func (v *CallBarringInfo5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.CallBarringFeatureListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes CallBarringInfo5 from BER/DER format.
func (v *CallBarringInfo5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CallBarringInfo5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarringInfo5", Cause: ber.ErrExtraData}
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
				tmp_sscode := SSCode5(val_sscode)
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
	// Decode nested SEQUENCE_OF (CallBarringFeatureList5)
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
	dec_callbarringfeaturelist, unmErr := UnmarshalBERCallBarringFeatureList5(tlv_callbarringfeaturelist)
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
			return &ber.DecodeError{Offset: offset, TypeName: "CallBarringInfo5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERCallBarringFeatureList5 encodes a CallBarringFeatureList5 list to BER.
func MarshalBERCallBarringFeatureList5(list CallBarringFeatureList5) ([]byte, error) {
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

// UnmarshalBERCallBarringFeatureList5 decodes a CallBarringFeatureList5 list from BER.
func UnmarshalBERCallBarringFeatureList5(data []byte) (CallBarringFeatureList5, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding CallBarringFeatureList5: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CallBarringFeatureList5", Cause: ber.ErrExtraData}
	}
	var result CallBarringFeatureList5
	offset := 0
	for offset < len(content) {
		var elem CallBarringFeature5
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

// MarshalBER encodes CallBarringFeature5 to BER format.
func (v *CallBarringFeature5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CallBarringFeature5 to DER format.
func (v *CallBarringFeature5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CallBarringFeature5 from BER/DER format.
func (v *CallBarringFeature5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CallBarringFeature5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarringFeature5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode5)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode5
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
				_, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				tmp_ssstatus := SSStatus5(rawVal_ssstatus)
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
			return &ber.DecodeError{Offset: offset, TypeName: "CallBarringFeature5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSData5 to BER format.
func (v *SSData5) MarshalBER() ([]byte, error) {
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
		enc_basicservicegrouplist, err := MarshalBERBasicServiceGroupList5(v.BasicServiceGroupList)
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

// MarshalDER encodes SSData5 to DER format.
func (v *SSData5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.BasicServiceGroupListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes SSData5 from BER/DER format.
func (v *SSData5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSData5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSData5", Cause: ber.ErrExtraData}
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
				tmp_sscode := SSCode5(val_sscode)
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
				_, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				tmp_ssstatus := SSStatus5(rawVal_ssstatus)
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
				// Decode nested CHOICE (SSSubscriptionOption5)
				_, n_sssubscriptionoption, _, tlvErr_sssubscriptionoption := ber.DecodeTLV(content[offset:])
				if tlvErr_sssubscriptionoption != nil {
					return fmt.Errorf("decoding ss-SubscriptionOption: %w", tlvErr_sssubscriptionoption)
				}
				var dec_sssubscriptionoption SSSubscriptionOption5
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
				// Decode nested SEQUENCE_OF (BasicServiceGroupList5)
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
				dec_basicservicegrouplist, unmErr := UnmarshalBERBasicServiceGroupList5(tlv_basicservicegrouplist)
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
				tmp_defaultpriority := EMLPPPriority5(val_defaultpriority)
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
				_, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nbrUser: %w", err)
				}
				decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
				if intErr != nil {
					return fmt.Errorf("decoding nbrUser: %w", intErr)
				}
				tmp_nbruser := MCBearers5(decVal_nbruser)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSData5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSSubscriptionOption5 to BER format.
func (v *SSSubscriptionOption5) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SSSubscriptionOption5ChoiceCliRestrictionOption:
		if v.CliRestrictionOption == nil {
			return nil, fmt.Errorf("choice SSSubscriptionOption5: cliRestrictionOption is nil")
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_0)
		return enc_0, nil
	case SSSubscriptionOption5ChoiceOverrideCategory:
		if v.OverrideCategory == nil {
			return nil, fmt.Errorf("choice SSSubscriptionOption5: overrideCategory is nil")
		}
		enc_1 := ber.EncodeEnumerated(int64(*v.OverrideCategory))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSSubscriptionOption5", v.Choice)
	}
}

// MarshalDER encodes SSSubscriptionOption5 to DER format.
func (v *SSSubscriptionOption5) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes SSSubscriptionOption5 from BER/DER format.
func (v *SSSubscriptionOption5) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSSubscriptionOption5 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSSubscriptionOption5: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SSSubscriptionOption5 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSubscriptionOption5", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SSSubscriptionOption5ChoiceCliRestrictionOption
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cliRestrictionOption: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding cliRestrictionOption: %w", intErr)
		}
		tmp := CliRestrictionOption5(decVal)
		v.CliRestrictionOption = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SSSubscriptionOption5ChoiceOverrideCategory
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding overrideCategory: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding overrideCategory: %w", intErr)
		}
		tmp := OverrideCategory5(decVal)
		v.OverrideCategory = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SSSubscriptionOption5 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SSForBSCode5 to BER format.
func (v *SSForBSCode5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSForBSCode5 to DER format.
func (v *SSForBSCode5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSForBSCode5 from BER/DER format.
func (v *SSForBSCode5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSForBSCode5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSForBSCode5", Cause: ber.ErrExtraData}
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
	v.SsCode = SSCode5(val_sscode)
	offset += n
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode5)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode5
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
				_, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding longFTN-Supported: %w", err)
				}
				_ = rawVal_longftnsupported
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSForBSCode5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GenericServiceInfo5 to BER format.
func (v *GenericServiceInfo5) MarshalBER() ([]byte, error) {
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
		enc_ccbsfeaturelist, err := MarshalBERCCBSFeatureList5(v.CcbsFeatureList)
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

// MarshalDER encodes GenericServiceInfo5 to DER format.
func (v *GenericServiceInfo5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.CcbsFeatureListIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes GenericServiceInfo5 from BER/DER format.
func (v *GenericServiceInfo5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding GenericServiceInfo5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GenericServiceInfo5", Cause: ber.ErrExtraData}
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
	v.SsStatus = SSStatus5(val_ssstatus)
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
				tmp_clirestrictionoption := CliRestrictionOption5(val_clirestrictionoption)
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
				_, n_maximumentitledpriority, rawVal_maximumentitledpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding maximumEntitledPriority: %w", err)
				}
				decVal_maximumentitledpriority, intErr := ber.DecodeIntegerValue(rawVal_maximumentitledpriority)
				if intErr != nil {
					return fmt.Errorf("decoding maximumEntitledPriority: %w", intErr)
				}
				tmp_maximumentitledpriority := EMLPPPriority5(decVal_maximumentitledpriority)
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
				_, n_defaultpriority, rawVal_defaultpriority, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding defaultPriority: %w", err)
				}
				decVal_defaultpriority, intErr := ber.DecodeIntegerValue(rawVal_defaultpriority)
				if intErr != nil {
					return fmt.Errorf("decoding defaultPriority: %w", intErr)
				}
				tmp_defaultpriority := EMLPPPriority5(decVal_defaultpriority)
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
				_, n_ccbsfeaturelist, rawVal_ccbsfeaturelist, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-FeatureList: %w", err)
				}
				reconstructed_ccbsfeaturelist := ber.EncodeSequence(rawVal_ccbsfeaturelist)
				dec_ccbsfeaturelist, unmErr := UnmarshalBERCCBSFeatureList5(reconstructed_ccbsfeaturelist)
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
				_, n_nbrsb, rawVal_nbrsb, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nbrSB: %w", err)
				}
				decVal_nbrsb, intErr := ber.DecodeIntegerValue(rawVal_nbrsb)
				if intErr != nil {
					return fmt.Errorf("decoding nbrSB: %w", intErr)
				}
				tmp_nbrsb := MaxMCBearers5(decVal_nbrsb)
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
				_, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nbrUser: %w", err)
				}
				decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
				if intErr != nil {
					return fmt.Errorf("decoding nbrUser: %w", intErr)
				}
				tmp_nbruser := MCBearers5(decVal_nbruser)
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
				_, n_nbrsn, rawVal_nbrsn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding nbrSN: %w", err)
				}
				decVal_nbrsn, intErr := ber.DecodeIntegerValue(rawVal_nbrsn)
				if intErr != nil {
					return fmt.Errorf("decoding nbrSN: %w", intErr)
				}
				tmp_nbrsn := MCBearers5(decVal_nbrsn)
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
			return &ber.DecodeError{Offset: offset, TypeName: "GenericServiceInfo5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERCCBSFeatureList5 encodes a CCBSFeatureList5 list to BER.
func MarshalBERCCBSFeatureList5(list CCBSFeatureList5) ([]byte, error) {
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

// UnmarshalBERCCBSFeatureList5 decodes a CCBSFeatureList5 list from BER.
func UnmarshalBERCCBSFeatureList5(data []byte) (CCBSFeatureList5, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding CCBSFeatureList5: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CCBSFeatureList5", Cause: ber.ErrExtraData}
	}
	var result CCBSFeatureList5
	offset := 0
	for offset < len(content) {
		var elem CCBSFeature5
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

// MarshalBER encodes CCBSFeature5 to BER format.
func (v *CCBSFeature5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CCBSFeature5 to DER format.
func (v *CCBSFeature5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CCBSFeature5 from BER/DER format.
func (v *CCBSFeature5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CCBSFeature5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CCBSFeature5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ccbs-Index
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_ccbsindex, rawVal_ccbsindex, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Index: %w", err)
				}
				decVal_ccbsindex, intErr := ber.DecodeIntegerValue(rawVal_ccbsindex)
				if intErr != nil {
					return fmt.Errorf("decoding ccbs-Index: %w", intErr)
				}
				tmp_ccbsindex := CCBSIndex5(decVal_ccbsindex)
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
				_, n_bsubscribernumber, rawVal_bsubscribernumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding b-subscriberNumber: %w", err)
				}
				tmp_bsubscribernumber := ISDNAddressString5(rawVal_bsubscribernumber)
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
				_, n_bsubscribersubaddress, rawVal_bsubscribersubaddress, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding b-subscriberSubaddress: %w", err)
				}
				tmp_bsubscribersubaddress := ISDNSubaddressString5(rawVal_bsubscribersubaddress)
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
				_, n_basicservicegroup, innerData_basicservicegroup, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding basicServiceGroup: %w", err)
				}
				// Decode inner value from explicit tag wrapper
				var dec_basicservicegroup BasicServiceCode5
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
			return &ber.DecodeError{Offset: offset, TypeName: "CCBSFeature5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes InterrogateSSRes5 to BER format.
func (v *InterrogateSSRes5) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case InterrogateSSRes5ChoiceSsStatus:
		enc_0 := ber.EncodeOctetString([]byte(*v.SsStatus))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case InterrogateSSRes5ChoiceBasicServiceGroupList:
		if v.BasicServiceGroupList == nil {
			return nil, fmt.Errorf("choice InterrogateSSRes5: basicServiceGroupList is nil")
		}
		enc_1, err := MarshalBERBasicServiceGroupList5(v.BasicServiceGroupList)
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_1)
		return enc_1, nil
	case InterrogateSSRes5ChoiceForwardingFeatureList:
		if v.ForwardingFeatureList == nil {
			return nil, fmt.Errorf("choice InterrogateSSRes5: forwardingFeatureList is nil")
		}
		enc_2, err := MarshalBERForwardingFeatureList5(v.ForwardingFeatureList)
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingFeatureList: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	case InterrogateSSRes5ChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("choice InterrogateSSRes5: genericServiceInfo is nil")
		}
		enc_3, err := v.GenericServiceInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for InterrogateSSRes5", v.Choice)
	}
}

// MarshalDER encodes InterrogateSSRes5 to DER format.
func (v *InterrogateSSRes5) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case InterrogateSSRes5ChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("choice InterrogateSSRes5: genericServiceInfo is nil")
		}
		enc_der_3, err := v.GenericServiceInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo: %w", err)
		}
		enc_der_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_der_3)
		return enc_der_3, nil
	}
	return v.MarshalBER()
}

// UnmarshalBER decodes InterrogateSSRes5 from BER/DER format.
func (v *InterrogateSSRes5) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for InterrogateSSRes5 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InterrogateSSRes5: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding InterrogateSSRes5 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InterrogateSSRes5", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = InterrogateSSRes5ChoiceSsStatus
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ss-Status: %w", tlvErr)
		}
		tmp := SSStatus5(rawVal)
		v.SsStatus = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = InterrogateSSRes5ChoiceBasicServiceGroupList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding basicServiceGroupList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERBasicServiceGroupList5(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding basicServiceGroupList: %w", unmErr)
		}
		v.BasicServiceGroupList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = InterrogateSSRes5ChoiceForwardingFeatureList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding forwardingFeatureList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERForwardingFeatureList5(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding forwardingFeatureList: %w", unmErr)
		}
		v.ForwardingFeatureList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = InterrogateSSRes5ChoiceGenericServiceInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding genericServiceInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec GenericServiceInfo5
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding genericServiceInfo: %w", unmErr)
		}
		v.GenericServiceInfo = &dec
	} else {
		return fmt.Errorf("unknown tag %s for InterrogateSSRes5 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes USSDArg5 to BER format.
func (v *USSDArg5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes USSDArg5 to DER format.
func (v *USSDArg5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes USSDArg5 from BER/DER format.
func (v *USSDArg5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding USSDArg5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "USSDArg5", Cause: ber.ErrExtraData}
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
	v.UssdDataCodingScheme = USSDDataCodingScheme5(val_ussddatacodingscheme)
	offset += n
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	val_ussdstring, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ussd-String: %w", err)
	}
	v.UssdString = USSDString5(val_ussdstring)
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
				tmp_alertingpattern := AlertingPattern5(val_alertingpattern)
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
				_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				tmp_msisdn := ISDNAddressString5(rawVal_msisdn)
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
			return &ber.DecodeError{Offset: offset, TypeName: "USSDArg5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes USSDRes5 to BER format.
func (v *USSDRes5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes USSDRes5 to DER format.
func (v *USSDRes5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes USSDRes5 from BER/DER format.
func (v *USSDRes5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding USSDRes5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "USSDRes5", Cause: ber.ErrExtraData}
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
	v.UssdDataCodingScheme = USSDDataCodingScheme5(val_ussddatacodingscheme)
	offset += n
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	val_ussdstring, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ussd-String: %w", err)
	}
	v.UssdString = USSDString5(val_ussdstring)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "USSDRes5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSSList5 encodes a SSList5 list to BER.
func MarshalBERSSList5(list SSList5) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSSList5 decodes a SSList5 list from BER.
func UnmarshalBERSSList5(data []byte) (SSList5, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSList5: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSList5", Cause: ber.ErrExtraData}
	}
	var result SSList5
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, SSCode5(val))
		offset += n
	}
	return result, nil
}

// MarshalBERSSInfoList5 encodes a SSInfoList5 list to BER.
func MarshalBERSSInfoList5(list SSInfoList5) ([]byte, error) {
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

// UnmarshalBERSSInfoList5 decodes a SSInfoList5 list from BER.
func UnmarshalBERSSInfoList5(data []byte) (SSInfoList5, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSInfoList5: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSInfoList5", Cause: ber.ErrExtraData}
	}
	var result SSInfoList5
	offset := 0
	for offset < len(content) {
		var elem SSInfo5
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

// MarshalBERBasicServiceGroupList5 encodes a BasicServiceGroupList5 list to BER.
func MarshalBERBasicServiceGroupList5(list BasicServiceGroupList5) ([]byte, error) {
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

// UnmarshalBERBasicServiceGroupList5 decodes a BasicServiceGroupList5 list from BER.
func UnmarshalBERBasicServiceGroupList5(data []byte) (BasicServiceGroupList5, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding BasicServiceGroupList5: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BasicServiceGroupList5", Cause: ber.ErrExtraData}
	}
	var result BasicServiceGroupList5
	offset := 0
	for offset < len(content) {
		var elem BasicServiceCode5
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

// MarshalBER encodes SSInvocationNotificationArg5 to BER format.
func (v *SSInvocationNotificationArg5) MarshalBER() ([]byte, error) {
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
		enc_sseventspecification, err := MarshalBERSSEventSpecification5(v.SsEventSpecification)
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

// MarshalDER encodes SSInvocationNotificationArg5 to DER format.
func (v *SSInvocationNotificationArg5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// ITU-T X.690 (02/2021) Section 10.1 requires DER length forms to be definite.
	derValue := *v
	derValue.SsEventSpecificationIndef_ = false
	v = &derValue
	return v.MarshalBER()
}

// UnmarshalBER decodes SSInvocationNotificationArg5 from BER/DER format.
func (v *SSInvocationNotificationArg5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSInvocationNotificationArg5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInvocationNotificationArg5", Cause: ber.ErrExtraData}
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
	_, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	v.Imsi = IMSI5(rawVal_imsi)
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
	_, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	v.Msisdn = ISDNAddressString5(rawVal_msisdn)
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
	_, n_ssevent, rawVal_ssevent, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Event: %w", err)
	}
	v.SsEvent = SSCode5(rawVal_ssevent)
	offset += n_ssevent
	// Decode ss-EventSpecification
	v.SsEventSpecificationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				_, n_sseventspecification, rawVal_sseventspecification, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-EventSpecification: %w", err)
				}
				reconstructed_sseventspecification := ber.EncodeSequence(rawVal_sseventspecification)
				dec_sseventspecification, unmErr := UnmarshalBERSSEventSpecification5(reconstructed_sseventspecification)
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
				_, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding extensionContainer: %w", err)
				}
				reconstructed_extensioncontainer := ber.EncodeSequence(rawVal_extensioncontainer)
				var dec_extensioncontainer ExtensionContainer5
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
				_, n_bsubscribernumber, rawVal_bsubscribernumber, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding b-subscriberNumber: %w", err)
				}
				tmp_bsubscribernumber := ISDNAddressString5(rawVal_bsubscribernumber)
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
				_, n_ccbsrequeststate, rawVal_ccbsrequeststate, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-RequestState: %w", err)
				}
				decVal_ccbsrequeststate, intErr := ber.DecodeIntegerValue(rawVal_ccbsrequeststate)
				if intErr != nil {
					return fmt.Errorf("decoding ccbs-RequestState: %w", intErr)
				}
				tmp_ccbsrequeststate := CCBSRequestState5(decVal_ccbsrequeststate)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSInvocationNotificationArg5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSInvocationNotificationRes5 to BER format.
func (v *SSInvocationNotificationRes5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSInvocationNotificationRes5 to DER format.
func (v *SSInvocationNotificationRes5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSInvocationNotificationRes5 from BER/DER format.
func (v *SSInvocationNotificationRes5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSInvocationNotificationRes5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInvocationNotificationRes5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer5)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer5
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSInvocationNotificationRes5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSSEventSpecification5 encodes a SSEventSpecification5 list to BER.
func MarshalBERSSEventSpecification5(list SSEventSpecification5) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSSEventSpecification5 decodes a SSEventSpecification5 list from BER.
func UnmarshalBERSSEventSpecification5(data []byte) (SSEventSpecification5, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSEventSpecification5: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSEventSpecification5", Cause: ber.ErrExtraData}
	}
	var result SSEventSpecification5
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, AddressString5(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes RegisterCCEntryArg5 to BER format.
func (v *RegisterCCEntryArg5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes RegisterCCEntryArg5 to DER format.
func (v *RegisterCCEntryArg5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RegisterCCEntryArg5 from BER/DER format.
func (v *RegisterCCEntryArg5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RegisterCCEntryArg5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterCCEntryArg5", Cause: ber.ErrExtraData}
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
	_, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	v.SsCode = SSCode5(rawVal_sscode)
	offset += n_sscode
	// Decode ccbs-Data
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_ccbsdata, rawVal_ccbsdata, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Data: %w", err)
				}
				reconstructed_ccbsdata := ber.EncodeSequence(rawVal_ccbsdata)
				var dec_ccbsdata CCBSData5
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
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterCCEntryArg5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CCBSData5 to BER format.
func (v *CCBSData5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CCBSData5 to DER format.
func (v *CCBSData5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes CCBSData5 from BER/DER format.
func (v *CCBSData5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CCBSData5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CCBSData5", Cause: ber.ErrExtraData}
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
	_, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ccbs-Feature: %w", err)
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
	_, n_translatedbnumber, rawVal_translatedbnumber, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding translatedB-Number: %w", err)
	}
	v.TranslatedBNumber = ISDNAddressString5(rawVal_translatedbnumber)
	offset += n_translatedbnumber
	// Decode serviceIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				_, n_serviceindicator, rawVal_serviceindicator, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding serviceIndicator: %w", err)
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
	_, n_callinfo, rawVal_callinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding callInfo: %w", err)
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
	_, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding networkSignalInfo: %w", err)
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
			return &ber.DecodeError{Offset: offset, TypeName: "CCBSData5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RegisterCCEntryRes5 to BER format.
func (v *RegisterCCEntryRes5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes RegisterCCEntryRes5 to DER format.
func (v *RegisterCCEntryRes5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes RegisterCCEntryRes5 from BER/DER format.
func (v *RegisterCCEntryRes5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RegisterCCEntryRes5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterCCEntryRes5", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ccbs-Feature
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				_, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Feature: %w", err)
				}
				reconstructed_ccbsfeature := ber.EncodeSequence(rawVal_ccbsfeature)
				var dec_ccbsfeature CCBSFeature5
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
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterCCEntryRes5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EraseCCEntryArg5 to BER format.
func (v *EraseCCEntryArg5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes EraseCCEntryArg5 to DER format.
func (v *EraseCCEntryArg5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EraseCCEntryArg5 from BER/DER format.
func (v *EraseCCEntryArg5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EraseCCEntryArg5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EraseCCEntryArg5", Cause: ber.ErrExtraData}
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
	_, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	v.SsCode = SSCode5(rawVal_sscode)
	offset += n_sscode
	// Decode ccbs-Index
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_ccbsindex, rawVal_ccbsindex, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ccbs-Index: %w", err)
				}
				decVal_ccbsindex, intErr := ber.DecodeIntegerValue(rawVal_ccbsindex)
				if intErr != nil {
					return fmt.Errorf("decoding ccbs-Index: %w", intErr)
				}
				tmp_ccbsindex := CCBSIndex5(decVal_ccbsindex)
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
			return &ber.DecodeError{Offset: offset, TypeName: "EraseCCEntryArg5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EraseCCEntryRes5 to BER format.
func (v *EraseCCEntryRes5) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes EraseCCEntryRes5 to DER format.
func (v *EraseCCEntryRes5) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes EraseCCEntryRes5 from BER/DER format.
func (v *EraseCCEntryRes5) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EraseCCEntryRes5 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EraseCCEntryRes5", Cause: ber.ErrExtraData}
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
	_, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	v.SsCode = SSCode5(rawVal_sscode)
	offset += n_sscode
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				_, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:])
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				tmp_ssstatus := SSStatus5(rawVal_ssstatus)
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
			return &ber.DecodeError{Offset: offset, TypeName: "EraseCCEntryRes5", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
