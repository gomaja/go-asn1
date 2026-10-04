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

	// MaxNumOfCCBSRequests6 is the integer constant for maxNumOfCCBS-Requests.
	MaxNumOfCCBSRequests6 int64 = 5

	// MaxUSSDStringLength6 is the integer constant for maxUSSD-StringLength.
	MaxUSSDStringLength6 int64 = 160

	// MaxNumOfSS6 is the integer constant for maxNumOfSS.
	MaxNumOfSS6 int64 = 30

	// MaxNumOfBasicServiceGroups6 is the integer constant for maxNumOfBasicServiceGroups.
	MaxNumOfBasicServiceGroups6 int64 = 13

	// MaxEventSpecification6 is the integer constant for maxEventSpecification.
	MaxEventSpecification6 int64 = 2
)

// RegisterSSArg6 represents the ASN.1 type RegisterSS-Arg (SEQUENCE).
type RegisterSSArg6 struct {
	SsCode                SSCode6                `asn1:""`
	BasicService          *BasicServiceCode6     `asn1:",optional" json:"BasicService,omitempty"`
	ForwardedToNumber     *AddressString6        `asn1:"tag:4,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString6 `asn1:"tag:6,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	NoReplyConditionTime  *NoReplyConditionTime6 `asn1:"tag:5,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	DefaultPriority       *EMLPPPriority6        `asn1:"tag:7,context,implicit,optional" json:"DefaultPriority,omitempty"`
	NbrUser               *MCBearers6            `asn1:"tag:8,context,implicit,optional" json:"NbrUser,omitempty"`
	LongFTNSupported      *struct{}              `asn1:"tag:9,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
	berOriginal_          []byte                 `asn1:"-" json:"-"`
	berSnapshot_          []byte                 `asn1:"-" json:"-"`
}

// NoReplyConditionTime6 represents the ASN.1 type NoReplyConditionTime (INTEGER).
type NoReplyConditionTime6 = int64

// SSInfo6 choice constants.
const (
	SSInfo6ChoiceForwardingInfo  = 1
	SSInfo6ChoiceCallBarringInfo = 2
	SSInfo6ChoiceSsData          = 3
)

// SSInfo6 represents the ASN.1 CHOICE type SS-Info.
type SSInfo6 struct {
	Choice          int
	berOriginal_    []byte            `json:"-"`
	berSnapshot_    []byte            `json:"-"`
	ForwardingInfo  *ForwardingInfo6  `json:"ForwardingInfo,omitempty"`
	CallBarringInfo *CallBarringInfo6 `json:"CallBarringInfo,omitempty"`
	SsData          *SSData6          `json:"SsData,omitempty"`
}

// NewSSInfo6ForwardingInfo creates a SSInfo6 with the forwardingInfo alternative.
func NewSSInfo6ForwardingInfo(v ForwardingInfo6) SSInfo6 {
	return SSInfo6{
		Choice:         SSInfo6ChoiceForwardingInfo,
		ForwardingInfo: &v,
	}
}

// NewSSInfo6CallBarringInfo creates a SSInfo6 with the callBarringInfo alternative.
func NewSSInfo6CallBarringInfo(v CallBarringInfo6) SSInfo6 {
	return SSInfo6{
		Choice:          SSInfo6ChoiceCallBarringInfo,
		CallBarringInfo: &v,
	}
}

// NewSSInfo6SsData creates a SSInfo6 with the ss-Data alternative.
func NewSSInfo6SsData(v SSData6) SSInfo6 {
	return SSInfo6{
		Choice: SSInfo6ChoiceSsData,
		SsData: &v,
	}
}

// ForwardingInfo6 represents the ASN.1 type ForwardingInfo (SEQUENCE).
type ForwardingInfo6 struct {
	SsCode                      *SSCode6                `asn1:",optional" json:"SsCode,omitempty"`
	ForwardingFeatureList       *ForwardingFeatureList6 `asn1:""`
	ForwardingFeatureListIndef_ bool                    `asn1:"-" json:"-"`
	ExtCount_                   int64                   `asn1:"-" json:"-"`
	ExtPresent_                 []bool                  `asn1:"-" json:"-"`
	ExtData_                    [][]byte                `asn1:"-" json:"-"`
	berOriginal_                []byte                  `asn1:"-" json:"-"`
	berSnapshot_                []byte                  `asn1:"-" json:"-"`
}

// ForwardingFeatureList6 represents the ASN.1 type ForwardingFeatureList (SEQUENCE_OF).
type ForwardingFeatureList6 struct {
	Values       []ForwardingFeature6 `json:"Values"`
	berOriginal_ []byte               `json:"-"`
	berSnapshot_ []byte               `json:"-"`
}

// ForwardingFeature6 represents the ASN.1 type ForwardingFeature (SEQUENCE).
type ForwardingFeature6 struct {
	BasicService          *BasicServiceCode6     `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus              *SSStatus6             `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ForwardedToNumber     *ISDNAddressString6    `asn1:"tag:5,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString6 `asn1:"tag:8,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	ForwardingOptions     *ForwardingOptions6    `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	NoReplyConditionTime  *NoReplyConditionTime6 `asn1:"tag:7,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	LongForwardedToNumber *FTNAddressString6     `asn1:"tag:9,context,implicit,optional" json:"LongForwardedToNumber,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
	berOriginal_          []byte                 `asn1:"-" json:"-"`
	berSnapshot_          []byte                 `asn1:"-" json:"-"`
}

// SSStatus6 represents the ASN.1 type SS-Status (OCTET_STRING).
type SSStatus6 = []byte

// ForwardingOptions6 represents the ASN.1 type ForwardingOptions (OCTET_STRING).
type ForwardingOptions6 = []byte

// CallBarringInfo6 represents the ASN.1 type CallBarringInfo (SEQUENCE).
type CallBarringInfo6 struct {
	SsCode                       *SSCode6                 `asn1:",optional" json:"SsCode,omitempty"`
	CallBarringFeatureList       *CallBarringFeatureList6 `asn1:""`
	CallBarringFeatureListIndef_ bool                     `asn1:"-" json:"-"`
	ExtCount_                    int64                    `asn1:"-" json:"-"`
	ExtPresent_                  []bool                   `asn1:"-" json:"-"`
	ExtData_                     [][]byte                 `asn1:"-" json:"-"`
	berOriginal_                 []byte                   `asn1:"-" json:"-"`
	berSnapshot_                 []byte                   `asn1:"-" json:"-"`
}

// CallBarringFeatureList6 represents the ASN.1 type CallBarringFeatureList (SEQUENCE_OF).
type CallBarringFeatureList6 struct {
	Values       []CallBarringFeature6 `json:"Values"`
	berOriginal_ []byte                `json:"-"`
	berSnapshot_ []byte                `json:"-"`
}

// CallBarringFeature6 represents the ASN.1 type CallBarringFeature (SEQUENCE).
type CallBarringFeature6 struct {
	BasicService *BasicServiceCode6 `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSStatus6         `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64              `asn1:"-" json:"-"`
	ExtPresent_  []bool             `asn1:"-" json:"-"`
	ExtData_     [][]byte           `asn1:"-" json:"-"`
	berOriginal_ []byte             `asn1:"-" json:"-"`
	berSnapshot_ []byte             `asn1:"-" json:"-"`
}

// SSData6 represents the ASN.1 type SS-Data (SEQUENCE).
type SSData6 struct {
	SsCode                      *SSCode6                `asn1:",optional" json:"SsCode,omitempty"`
	SsStatus                    *SSStatus6              `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	SsSubscriptionOption        *SSSubscriptionOption6  `asn1:",optional" json:"SsSubscriptionOption,omitempty"`
	BasicServiceGroupList       *BasicServiceGroupList6 `asn1:",optional" json:"BasicServiceGroupList,omitempty"`
	BasicServiceGroupListIndef_ bool                    `asn1:"-" json:"-"`
	DefaultPriority             *EMLPPPriority6         `asn1:",optional" json:"DefaultPriority,omitempty"`
	NbrUser                     *MCBearers6             `asn1:"tag:5,context,implicit,optional" json:"NbrUser,omitempty"`
	ExtCount_                   int64                   `asn1:"-" json:"-"`
	ExtPresent_                 []bool                  `asn1:"-" json:"-"`
	ExtData_                    [][]byte                `asn1:"-" json:"-"`
	berOriginal_                []byte                  `asn1:"-" json:"-"`
	berSnapshot_                []byte                  `asn1:"-" json:"-"`
}

// SSSubscriptionOption6 choice constants.
const (
	SSSubscriptionOption6ChoiceCliRestrictionOption = 1
	SSSubscriptionOption6ChoiceOverrideCategory     = 2
)

// SSSubscriptionOption6 represents the ASN.1 CHOICE type SS-SubscriptionOption.
type SSSubscriptionOption6 struct {
	Choice               int
	berOriginal_         []byte                 `json:"-"`
	berSnapshot_         []byte                 `json:"-"`
	CliRestrictionOption *CliRestrictionOption6 `json:"CliRestrictionOption,omitempty"`
	OverrideCategory     *OverrideCategory6     `json:"OverrideCategory,omitempty"`
}

// NewSSSubscriptionOption6CliRestrictionOption creates a SSSubscriptionOption6 with the cliRestrictionOption alternative.
func NewSSSubscriptionOption6CliRestrictionOption(v CliRestrictionOption6) SSSubscriptionOption6 {
	return SSSubscriptionOption6{
		Choice:               SSSubscriptionOption6ChoiceCliRestrictionOption,
		CliRestrictionOption: &v,
	}
}

// NewSSSubscriptionOption6OverrideCategory creates a SSSubscriptionOption6 with the overrideCategory alternative.
func NewSSSubscriptionOption6OverrideCategory(v OverrideCategory6) SSSubscriptionOption6 {
	return SSSubscriptionOption6{
		Choice:           SSSubscriptionOption6ChoiceOverrideCategory,
		OverrideCategory: &v,
	}
}

// CliRestrictionOption6 represents the ASN.1 ENUMERATED type CliRestrictionOption.
type CliRestrictionOption6 int64

const (
	CliRestrictionOption6Permanent                  CliRestrictionOption6 = 0
	CliRestrictionOption6TemporaryDefaultRestricted CliRestrictionOption6 = 1
	CliRestrictionOption6TemporaryDefaultAllowed    CliRestrictionOption6 = 2
)

func (v CliRestrictionOption6) String() string {
	switch v {
	case CliRestrictionOption6Permanent:
		return "permanent"
	case CliRestrictionOption6TemporaryDefaultRestricted:
		return "temporaryDefaultRestricted"
	case CliRestrictionOption6TemporaryDefaultAllowed:
		return "temporaryDefaultAllowed"
	default:
		return "unknown"
	}
}

// OverrideCategory6 represents the ASN.1 ENUMERATED type OverrideCategory.
type OverrideCategory6 int64

const (
	OverrideCategory6OverrideEnabled  OverrideCategory6 = 0
	OverrideCategory6OverrideDisabled OverrideCategory6 = 1
)

func (v OverrideCategory6) String() string {
	switch v {
	case OverrideCategory6OverrideEnabled:
		return "overrideEnabled"
	case OverrideCategory6OverrideDisabled:
		return "overrideDisabled"
	default:
		return "unknown"
	}
}

// SSForBSCode6 represents the ASN.1 type SS-ForBS-Code (SEQUENCE).
type SSForBSCode6 struct {
	SsCode           SSCode6            `asn1:""`
	BasicService     *BasicServiceCode6 `asn1:",optional" json:"BasicService,omitempty"`
	LongFTNSupported *struct{}          `asn1:"tag:4,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_        int64              `asn1:"-" json:"-"`
	ExtPresent_      []bool             `asn1:"-" json:"-"`
	ExtData_         [][]byte           `asn1:"-" json:"-"`
	berOriginal_     []byte             `asn1:"-" json:"-"`
	berSnapshot_     []byte             `asn1:"-" json:"-"`
}

// GenericServiceInfo6 represents the ASN.1 type GenericServiceInfo (SEQUENCE).
type GenericServiceInfo6 struct {
	SsStatus                SSStatus6              `asn1:""`
	CliRestrictionOption    *CliRestrictionOption6 `asn1:",optional" json:"CliRestrictionOption,omitempty"`
	MaximumEntitledPriority *EMLPPPriority6        `asn1:"tag:0,context,implicit,optional" json:"MaximumEntitledPriority,omitempty"`
	DefaultPriority         *EMLPPPriority6        `asn1:"tag:1,context,implicit,optional" json:"DefaultPriority,omitempty"`
	CcbsFeatureList         *CCBSFeatureList6      `asn1:"tag:2,context,implicit,optional" json:"CcbsFeatureList,omitempty"`
	CcbsFeatureListIndef_   bool                   `asn1:"-" json:"-"`
	NbrSB                   *MaxMCBearers6         `asn1:"tag:3,context,implicit,optional" json:"NbrSB,omitempty"`
	NbrUser                 *MCBearers6            `asn1:"tag:4,context,implicit,optional" json:"NbrUser,omitempty"`
	NbrSN                   *MCBearers6            `asn1:"tag:5,context,implicit,optional" json:"NbrSN,omitempty"`
	ExtCount_               int64                  `asn1:"-" json:"-"`
	ExtPresent_             []bool                 `asn1:"-" json:"-"`
	ExtData_                [][]byte               `asn1:"-" json:"-"`
	berOriginal_            []byte                 `asn1:"-" json:"-"`
	berSnapshot_            []byte                 `asn1:"-" json:"-"`
}

// CCBSFeatureList6 represents the ASN.1 type CCBS-FeatureList (SEQUENCE_OF).
type CCBSFeatureList6 struct {
	Values       []CCBSFeature6 `json:"Values"`
	berOriginal_ []byte         `json:"-"`
	berSnapshot_ []byte         `json:"-"`
}

// CCBSFeature6 represents the ASN.1 type CCBS-Feature (SEQUENCE).
type CCBSFeature6 struct {
	CcbsIndex             *CCBSIndex6            `asn1:"tag:0,context,implicit,optional" json:"CcbsIndex,omitempty"`
	BSubscriberNumber     *ISDNAddressString6    `asn1:"tag:1,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	BSubscriberSubaddress *ISDNSubaddressString6 `asn1:"tag:2,context,implicit,optional" json:"BSubscriberSubaddress,omitempty"`
	BasicServiceGroup     *BasicServiceCode6     `asn1:"tag:3,context,explicit,optional" json:"BasicServiceGroup,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
	berOriginal_          []byte                 `asn1:"-" json:"-"`
	berSnapshot_          []byte                 `asn1:"-" json:"-"`
}

// CCBSIndex6 represents the ASN.1 type CCBS-Index (INTEGER).
type CCBSIndex6 = int64

// InterrogateSSRes6 choice constants.
const (
	InterrogateSSRes6ChoiceSsStatus              = 1
	InterrogateSSRes6ChoiceBasicServiceGroupList = 2
	InterrogateSSRes6ChoiceForwardingFeatureList = 3
	InterrogateSSRes6ChoiceGenericServiceInfo    = 4
)

// InterrogateSSRes6 represents the ASN.1 CHOICE type InterrogateSS-Res.
type InterrogateSSRes6 struct {
	Choice                int
	berOriginal_          []byte                  `json:"-"`
	berSnapshot_          []byte                  `json:"-"`
	SsStatus              *SSStatus6              `json:"SsStatus,omitempty"`
	BasicServiceGroupList *BasicServiceGroupList6 `json:"BasicServiceGroupList,omitempty"`
	ForwardingFeatureList *ForwardingFeatureList6 `json:"ForwardingFeatureList,omitempty"`
	GenericServiceInfo    *GenericServiceInfo6    `json:"GenericServiceInfo,omitempty"`
}

// NewInterrogateSSRes6SsStatus creates a InterrogateSSRes6 with the ss-Status alternative.
func NewInterrogateSSRes6SsStatus(v SSStatus6) InterrogateSSRes6 {
	return InterrogateSSRes6{
		Choice:   InterrogateSSRes6ChoiceSsStatus,
		SsStatus: &v,
	}
}

// NewInterrogateSSRes6BasicServiceGroupList creates a InterrogateSSRes6 with the basicServiceGroupList alternative.
func NewInterrogateSSRes6BasicServiceGroupList(v *BasicServiceGroupList6) InterrogateSSRes6 {
	return InterrogateSSRes6{
		Choice:                InterrogateSSRes6ChoiceBasicServiceGroupList,
		BasicServiceGroupList: v,
	}
}

// NewInterrogateSSRes6ForwardingFeatureList creates a InterrogateSSRes6 with the forwardingFeatureList alternative.
func NewInterrogateSSRes6ForwardingFeatureList(v *ForwardingFeatureList6) InterrogateSSRes6 {
	return InterrogateSSRes6{
		Choice:                InterrogateSSRes6ChoiceForwardingFeatureList,
		ForwardingFeatureList: v,
	}
}

// NewInterrogateSSRes6GenericServiceInfo creates a InterrogateSSRes6 with the genericServiceInfo alternative.
func NewInterrogateSSRes6GenericServiceInfo(v GenericServiceInfo6) InterrogateSSRes6 {
	return InterrogateSSRes6{
		Choice:             InterrogateSSRes6ChoiceGenericServiceInfo,
		GenericServiceInfo: &v,
	}
}

// USSDArg6 represents the ASN.1 type USSD-Arg (SEQUENCE).
type USSDArg6 struct {
	UssdDataCodingScheme USSDDataCodingScheme6 `asn1:""`
	UssdString           USSDString6           `asn1:""`
	AlertingPattern      *AlertingPattern6     `asn1:",optional" json:"AlertingPattern,omitempty"`
	Msisdn               *ISDNAddressString6   `asn1:"tag:0,context,implicit,optional" json:"Msisdn,omitempty"`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	ExtData_             [][]byte              `asn1:"-" json:"-"`
	berOriginal_         []byte                `asn1:"-" json:"-"`
	berSnapshot_         []byte                `asn1:"-" json:"-"`
}

// USSDRes6 represents the ASN.1 type USSD-Res (SEQUENCE).
type USSDRes6 struct {
	UssdDataCodingScheme USSDDataCodingScheme6 `asn1:""`
	UssdString           USSDString6           `asn1:""`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	ExtData_             [][]byte              `asn1:"-" json:"-"`
	berOriginal_         []byte                `asn1:"-" json:"-"`
	berSnapshot_         []byte                `asn1:"-" json:"-"`
}

// USSDDataCodingScheme6 represents the ASN.1 type USSD-DataCodingScheme (OCTET_STRING).
type USSDDataCodingScheme6 = []byte

// USSDString6 represents the ASN.1 type USSD-String (OCTET_STRING).
type USSDString6 = []byte

// Password6 represents the ASN.1 type Password (NumericString).
type Password6 = string

// GuidanceInfo6 represents the ASN.1 ENUMERATED type GuidanceInfo.
type GuidanceInfo6 int64

const (
	GuidanceInfo6EnterPW         GuidanceInfo6 = 0
	GuidanceInfo6EnterNewPW      GuidanceInfo6 = 1
	GuidanceInfo6EnterNewPWAgain GuidanceInfo6 = 2
)

func (v GuidanceInfo6) String() string {
	switch v {
	case GuidanceInfo6EnterPW:
		return "enterPW"
	case GuidanceInfo6EnterNewPW:
		return "enterNewPW"
	case GuidanceInfo6EnterNewPWAgain:
		return "enterNewPW-Again"
	default:
		return "unknown"
	}
}

// SSList6 represents the ASN.1 type SS-List (SEQUENCE_OF).
type SSList6 struct {
	Values       []SSCode6 `json:"Values"`
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
}

// SSInfoList6 represents the ASN.1 type SS-InfoList (SEQUENCE_OF).
type SSInfoList6 struct {
	Values       []SSInfo6 `json:"Values"`
	berOriginal_ []byte    `json:"-"`
	berSnapshot_ []byte    `json:"-"`
}

// BasicServiceGroupList6 represents the ASN.1 type BasicServiceGroupList (SEQUENCE_OF).
type BasicServiceGroupList6 struct {
	Values       []BasicServiceCode6 `json:"Values"`
	berOriginal_ []byte              `json:"-"`
	berSnapshot_ []byte              `json:"-"`
}

// SSInvocationNotificationArg6 represents the ASN.1 type SS-InvocationNotificationArg (SEQUENCE).
type SSInvocationNotificationArg6 struct {
	Imsi                       IMSI6                  `asn1:"tag:0,context,implicit"`
	Msisdn                     ISDNAddressString6     `asn1:"tag:1,context,implicit"`
	SsEvent                    SSCode6                `asn1:"tag:2,context,implicit"`
	SsEventSpecification       *SSEventSpecification6 `asn1:"tag:3,context,implicit,optional" json:"SsEventSpecification,omitempty"`
	SsEventSpecificationIndef_ bool                   `asn1:"-" json:"-"`
	ExtensionContainer         *ExtensionContainer6   `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	BSubscriberNumber          *ISDNAddressString6    `asn1:"tag:5,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	CcbsRequestState           *CCBSRequestState6     `asn1:"tag:6,context,implicit,optional" json:"CcbsRequestState,omitempty"`
	ExtCount_                  int64                  `asn1:"-" json:"-"`
	ExtPresent_                []bool                 `asn1:"-" json:"-"`
	ExtData_                   [][]byte               `asn1:"-" json:"-"`
	berOriginal_               []byte                 `asn1:"-" json:"-"`
	berSnapshot_               []byte                 `asn1:"-" json:"-"`
}

// CCBSRequestState6 represents the ASN.1 ENUMERATED type CCBS-RequestState.
type CCBSRequestState6 int64

const (
	CCBSRequestState6Request   CCBSRequestState6 = 0
	CCBSRequestState6Recall    CCBSRequestState6 = 1
	CCBSRequestState6Active    CCBSRequestState6 = 2
	CCBSRequestState6Completed CCBSRequestState6 = 3
	CCBSRequestState6Suspended CCBSRequestState6 = 4
	CCBSRequestState6Frozen    CCBSRequestState6 = 5
	CCBSRequestState6Deleted   CCBSRequestState6 = 6
)

func (v CCBSRequestState6) String() string {
	switch v {
	case CCBSRequestState6Request:
		return "request"
	case CCBSRequestState6Recall:
		return "recall"
	case CCBSRequestState6Active:
		return "active"
	case CCBSRequestState6Completed:
		return "completed"
	case CCBSRequestState6Suspended:
		return "suspended"
	case CCBSRequestState6Frozen:
		return "frozen"
	case CCBSRequestState6Deleted:
		return "deleted"
	default:
		return "unknown"
	}
}

// SSInvocationNotificationRes6 represents the ASN.1 type SS-InvocationNotificationRes (SEQUENCE).
type SSInvocationNotificationRes6 struct {
	ExtensionContainer *ExtensionContainer6 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
	berOriginal_       []byte               `asn1:"-" json:"-"`
	berSnapshot_       []byte               `asn1:"-" json:"-"`
}

// SSEventSpecification6 represents the ASN.1 type SS-EventSpecification (SEQUENCE_OF).
type SSEventSpecification6 struct {
	Values       []AddressString6 `json:"Values"`
	berOriginal_ []byte           `json:"-"`
	berSnapshot_ []byte           `json:"-"`
}

// RegisterCCEntryArg6 represents the ASN.1 type RegisterCC-EntryArg (SEQUENCE).
type RegisterCCEntryArg6 struct {
	SsCode       SSCode6    `asn1:"tag:0,context,implicit"`
	CcbsData     *CCBSData6 `asn1:"tag:1,context,implicit,optional" json:"CcbsData,omitempty"`
	ExtCount_    int64      `asn1:"-" json:"-"`
	ExtPresent_  []bool     `asn1:"-" json:"-"`
	ExtData_     [][]byte   `asn1:"-" json:"-"`
	berOriginal_ []byte     `asn1:"-" json:"-"`
	berSnapshot_ []byte     `asn1:"-" json:"-"`
}

// CCBSData6 represents the ASN.1 type CCBS-Data (SEQUENCE).
type CCBSData6 struct {
	CcbsFeature       CCBSFeature6        `asn1:"tag:0,context,implicit"`
	TranslatedBNumber ISDNAddressString6  `asn1:"tag:1,context,implicit"`
	ServiceIndicator  *ServiceIndicator6  `asn1:"tag:2,context,implicit,optional" json:"ServiceIndicator,omitempty"`
	CallInfo          ExternalSignalInfo6 `asn1:"tag:3,context,implicit"`
	NetworkSignalInfo ExternalSignalInfo6 `asn1:"tag:4,context,implicit"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
	berOriginal_      []byte              `asn1:"-" json:"-"`
	berSnapshot_      []byte              `asn1:"-" json:"-"`
}

// ServiceIndicator6 represents the ASN.1 type ServiceIndicator (BIT_STRING).
type ServiceIndicator6 = runtime.BitString

// RegisterCCEntryRes6 represents the ASN.1 type RegisterCC-EntryRes (SEQUENCE).
type RegisterCCEntryRes6 struct {
	CcbsFeature  *CCBSFeature6 `asn1:"tag:0,context,implicit,optional" json:"CcbsFeature,omitempty"`
	ExtCount_    int64         `asn1:"-" json:"-"`
	ExtPresent_  []bool        `asn1:"-" json:"-"`
	ExtData_     [][]byte      `asn1:"-" json:"-"`
	berOriginal_ []byte        `asn1:"-" json:"-"`
	berSnapshot_ []byte        `asn1:"-" json:"-"`
}

// EraseCCEntryArg6 represents the ASN.1 type EraseCC-EntryArg (SEQUENCE).
type EraseCCEntryArg6 struct {
	SsCode       SSCode6     `asn1:"tag:0,context,implicit"`
	CcbsIndex    *CCBSIndex6 `asn1:"tag:1,context,implicit,optional" json:"CcbsIndex,omitempty"`
	ExtCount_    int64       `asn1:"-" json:"-"`
	ExtPresent_  []bool      `asn1:"-" json:"-"`
	ExtData_     [][]byte    `asn1:"-" json:"-"`
	berOriginal_ []byte      `asn1:"-" json:"-"`
	berSnapshot_ []byte      `asn1:"-" json:"-"`
}

// EraseCCEntryRes6 represents the ASN.1 type EraseCC-EntryRes (SEQUENCE).
type EraseCCEntryRes6 struct {
	SsCode       SSCode6    `asn1:"tag:0,context,implicit"`
	SsStatus     *SSStatus6 `asn1:"tag:1,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64      `asn1:"-" json:"-"`
	ExtPresent_  []bool     `asn1:"-" json:"-"`
	ExtData_     [][]byte   `asn1:"-" json:"-"`
	berOriginal_ []byte     `asn1:"-" json:"-"`
	berSnapshot_ []byte     `asn1:"-" json:"-"`
}

// MarshalBER encodes RegisterSSArg6 to BER format.
func (v *RegisterSSArg6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RegisterSSArg6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RegisterSSArg6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	children = append(children, enc_sscode...)
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, fmt.Errorf("encoding forwardedToNumber: %w", encodeErr_enc_forwardedtonumber)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, fmt.Errorf("encoding forwardedToNumber: %w", tagErr_enc_forwardedtonumber)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(opts, "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, fmt.Errorf("encoding forwardedToSubaddress: %w", encodeErr_enc_forwardedtosubaddress)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, fmt.Errorf("encoding forwardedToSubaddress: %w", tagErr_enc_forwardedtosubaddress)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := ber.CheckEncodedValue(opts, "noReplyConditionTime", "(5..30)", fmt.Sprint(int64(*v.NoReplyConditionTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		retagged_enc_noreplyconditiontime, tagErr_enc_noreplyconditiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_noreplyconditiontime)
		if tagErr_enc_noreplyconditiontime != nil {
			return nil, fmt.Errorf("encoding noReplyConditionTime: %w", tagErr_enc_noreplyconditiontime)
		}
		enc_noreplyconditiontime = retagged_enc_noreplyconditiontime
		children = append(children, enc_noreplyconditiontime...)
	}
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := ber.CheckEncodedValue(opts, "defaultPriority", "(0..15)", fmt.Sprint(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		retagged_enc_defaultpriority, tagErr_enc_defaultpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_defaultpriority)
		if tagErr_enc_defaultpriority != nil {
			return nil, fmt.Errorf("encoding defaultPriority: %w", tagErr_enc_defaultpriority)
		}
		enc_defaultpriority = retagged_enc_defaultpriority
		children = append(children, enc_defaultpriority...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := ber.CheckEncodedValue(opts, "nbrUser", "(1..7)", fmt.Sprint(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, fmt.Errorf("encoding nbrUser: %w", tagErr_enc_nbruser)
		}
		enc_nbruser = retagged_enc_nbruser
		children = append(children, enc_nbruser...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, fmt.Errorf("encoding longFTN-Supported: %w", tagErr_enc_longftnsupported)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes RegisterSSArg6 to DER format.
func (v *RegisterSSArg6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RegisterSSArg6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	children = append(children, enc_sscode...)
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, fmt.Errorf("encoding forwardedToNumber: %w", encodeErr_enc_forwardedtonumber)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, fmt.Errorf("encoding forwardedToNumber: %w", tagErr_enc_forwardedtonumber)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(nil, "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, fmt.Errorf("encoding forwardedToSubaddress: %w", encodeErr_enc_forwardedtosubaddress)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, fmt.Errorf("encoding forwardedToSubaddress: %w", tagErr_enc_forwardedtosubaddress)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := ber.CheckEncodedValue(nil, "noReplyConditionTime", "(5..30)", fmt.Sprint(int64(*v.NoReplyConditionTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		retagged_enc_noreplyconditiontime, tagErr_enc_noreplyconditiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_noreplyconditiontime)
		if tagErr_enc_noreplyconditiontime != nil {
			return nil, fmt.Errorf("encoding noReplyConditionTime: %w", tagErr_enc_noreplyconditiontime)
		}
		enc_noreplyconditiontime = retagged_enc_noreplyconditiontime
		children = append(children, enc_noreplyconditiontime...)
	}
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := ber.CheckEncodedValue(nil, "defaultPriority", "(0..15)", fmt.Sprint(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		retagged_enc_defaultpriority, tagErr_enc_defaultpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_defaultpriority)
		if tagErr_enc_defaultpriority != nil {
			return nil, fmt.Errorf("encoding defaultPriority: %w", tagErr_enc_defaultpriority)
		}
		enc_defaultpriority = retagged_enc_defaultpriority
		children = append(children, enc_defaultpriority...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := ber.CheckEncodedValue(nil, "nbrUser", "(1..7)", fmt.Sprint(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, fmt.Errorf("encoding nbrUser: %w", tagErr_enc_nbruser)
		}
		enc_nbruser = retagged_enc_nbruser
		children = append(children, enc_nbruser...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, fmt.Errorf("encoding longFTN-Supported: %w", tagErr_enc_longftnsupported)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
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
		return nil, fmt.Errorf("encoding RegisterSSArg6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RegisterSSArg6 from BER/DER format.
func (v *RegisterSSArg6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RegisterSSArg6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RegisterSSArg6{}
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
		return fmt.Errorf("decoding RegisterSSArg6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterSSArg6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	v.SsCode = SSCode6(val_sscode)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode6)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode6
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicservice")...); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
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
				decodedTag_forwardedtonumber, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding forwardedToNumber: %w", err)
				}
				if decodedTag_forwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_forwardedtonumber.Number != 4 {
					return fmt.Errorf("decoding forwardedToNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtonumber)
				}
				decVal_forwardedtonumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtonumber.Constructed, rawVal_forwardedtonumber, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding forwardedToNumber: %w", octetErr)
				}
				tmp_forwardedtonumber := AddressString6(decVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				if offset < 0 || offset >
					len(content) || n_forwardedtonumber < 0 || n_forwardedtonumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtonumber
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
				decodedTag_forwardedtosubaddress, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding forwardedToSubaddress: %w", err)
				}
				if decodedTag_forwardedtosubaddress.Class != tag.ClassContextSpecific || decodedTag_forwardedtosubaddress.Number != 6 {
					return fmt.Errorf("decoding forwardedToSubaddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtosubaddress)
				}
				decVal_forwardedtosubaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtosubaddress.Constructed, rawVal_forwardedtosubaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding forwardedToSubaddress: %w", octetErr)
				}
				tmp_forwardedtosubaddress := ISDNSubaddressString6(decVal_forwardedtosubaddress)
				v.ForwardedToSubaddress = &tmp_forwardedtosubaddress
				if offset < 0 || offset >
					len(content) || n_forwardedtosubaddress < 0 || n_forwardedtosubaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtosubaddress
				if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
					if constraintErr := ber.CheckDecodedLength(opts, "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
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
				decodedTag_noreplyconditiontime, n_noreplyconditiontime, rawVal_noreplyconditiontime, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_noreplyconditiontime := NoReplyConditionTime6(decVal_noreplyconditiontime)
				v.NoReplyConditionTime = &tmp_noreplyconditiontime
				if offset < 0 || offset >
					len(content) || n_noreplyconditiontime < 0 || n_noreplyconditiontime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_noreplyconditiontime
				if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
					if constraintErr := ber.CheckDecodedValue(opts, "noReplyConditionTime", "(5..30)", fmt.Sprint(int64(*v.NoReplyConditionTime))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode defaultPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				decodedTag_defaultpriority, n_defaultpriority, rawVal_defaultpriority, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_defaultpriority := EMLPPPriority6(decVal_defaultpriority)
				v.DefaultPriority = &tmp_defaultpriority
				if offset < 0 || offset >
					len(content) || n_defaultpriority < 0 || n_defaultpriority >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_defaultpriority
				if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
					if constraintErr := ber.CheckDecodedValue(opts, "defaultPriority", "(0..15)", fmt.Sprint(int64(*v.DefaultPriority))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode nbrUser
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 {
				decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_nbruser := MCBearers6(decVal_nbruser)
				v.NbrUser = &tmp_nbruser
				if offset < 0 || offset >
					len(content) || n_nbruser < 0 || n_nbruser > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nbruser
				if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
					if constraintErr := ber.CheckDecodedValue(opts, "nbrUser", "(1..7)", fmt.Sprint(int64(*v.NbrUser))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode longFTN-Supported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_longftnsupported, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:], opts...)
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
				if offset < 0 || offset >
					len(content) || n_longftnsupported < 0 || n_longftnsupported >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_longftnsupported
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterSSArg6", Cause: extErr_}
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

// MarshalBER encodes SSInfo6 to BER format.
func (v *SSInfo6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSInfo6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SSInfo6ChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInfo6: forwardingInfo is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.ForwardingInfo.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingInfo: %w", err)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding forwardingInfo: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SSInfo6ChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInfo6: callBarringInfo is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.CallBarringInfo.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding callBarringInfo: %w", err)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding callBarringInfo: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SSInfo6ChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("%w: choice SSInfo6: ss-Data is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.SsData.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding ss-Data: %w", err)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding ss-Data: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSInfo6", v.Choice)
	}
}

// MarshalDER encodes SSInfo6 to DER format.
func (v *SSInfo6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SSInfo6ChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInfo6: forwardingInfo is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.ForwardingInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingInfo: %w", err)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, fmt.Errorf("encoding forwardingInfo: %w", tagErr_enc_der_0)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, fmt.Errorf("encoding forwardingInfo as DER: %w", derErr)
		}
		return enc_der_0, nil
	case SSInfo6ChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInfo6: callBarringInfo is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.CallBarringInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding callBarringInfo: %w", err)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding callBarringInfo: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding callBarringInfo as DER: %w", derErr)
		}
		return enc_der_1, nil
	case SSInfo6ChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("%w: choice SSInfo6: ss-Data is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.SsData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ss-Data: %w", err)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, fmt.Errorf("encoding ss-Data: %w", tagErr_enc_der_2)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding ss-Data as DER: %w", derErr)
		}
		return enc_der_2, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSInfo6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSInfo6 from BER/DER format.
func (v *SSInfo6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSInfo6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
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
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSInfo6{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSInfo6 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSInfo6: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SSInfo6 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInfo6", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = SSInfo6ChoiceForwardingInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding forwardingInfo: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ForwardingInfo6
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding forwardingInfo: %w", unmErr)
		}
		v.ForwardingInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = SSInfo6ChoiceCallBarringInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding callBarringInfo: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec CallBarringInfo6
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding callBarringInfo: %w", unmErr)
		}
		v.CallBarringInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = SSInfo6ChoiceSsData
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding ss-Data: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec SSData6
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding ss-Data: %w", unmErr)
		}
		v.SsData = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SSInfo6 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ForwardingInfo6 to BER format.
func (v *ForwardingInfo6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ForwardingInfo6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
		}
		children = append(children, enc_sscode...)
	}
	if v.ForwardingFeatureList == nil {
		return nil, fmt.Errorf("encoding forwardingFeatureList: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
		if constraintErr := ber.CheckEncodedLength(opts, "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_forwardingfeaturelist, err := MarshalBERForwardingFeatureList6(v.ForwardingFeatureList, opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ForwardingInfo6 to DER format.
func (v *ForwardingInfo6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
		}
		children = append(children, enc_sscode...)
	}
	if v.ForwardingFeatureList == nil {
		return nil, fmt.Errorf("encoding forwardingFeatureList: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
		if constraintErr := ber.CheckEncodedLength(nil, "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_forwardingfeaturelist, err := MarshalDERForwardingFeatureList6(v.ForwardingFeatureList)
	if err != nil {
		return nil, fmt.Errorf("encoding forwardingFeatureList: %w", err)
	}
	children = append(children, enc_forwardingfeaturelist...)
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
		return nil, fmt.Errorf("encoding ForwardingInfo6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingInfo6 from BER/DER format.
func (v *ForwardingInfo6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ForwardingInfo6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ForwardingInfo6{}
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
		return fmt.Errorf("decoding ForwardingInfo6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingInfo6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				tmp_sscode := SSCode6(val_sscode)
				v.SsCode = &tmp_sscode
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode forwardingFeatureList
	if offset >= len(content) {
		return fmt.Errorf("missing required field forwardingFeatureList")
	}
	v.ForwardingFeatureListIndef_ = false
	// Decode nested SEQUENCE_OF (ForwardingFeatureList6)
	_, n_forwardingfeaturelist, _, tlvErr_forwardingfeaturelist := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_forwardingfeaturelist != nil {
		return fmt.Errorf("decoding forwardingFeatureList: %w", tlvErr_forwardingfeaturelist)
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
			v.ForwardingFeatureListIndef_ = true
		}
	}
	dec_forwardingfeaturelist, unmErr := UnmarshalBERForwardingFeatureList6(tlv_forwardingfeaturelist, ber.ChildDecodeOptions(opts, "forwardingFeatureList")...)
	if unmErr != nil {
		return fmt.Errorf("decoding forwardingFeatureList: %w", unmErr)
	}
	v.ForwardingFeatureList = dec_forwardingfeaturelist
	if offset < 0 || offset >
		len(content) || n_forwardingfeaturelist < 0 || n_forwardingfeaturelist >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_forwardingfeaturelist
	if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
		if constraintErr := ber.CheckDecodedLength(opts, "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingInfo6", Cause: extErr_}
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

// MarshalBERForwardingFeatureList6 encodes a ForwardingFeatureList6 list to BER.
func MarshalBERForwardingFeatureList6(collection *ForwardingFeatureList6, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERForwardingFeatureList6(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERForwardingFeatureList6(collection *ForwardingFeatureList6, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedLength(opts, "ForwardingFeatureList6", "SIZE (1..13)", len(list)); constraintErr != nil {
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

// MarshalDERForwardingFeatureList6 encodes a ForwardingFeatureList6 list to DER.
func MarshalDERForwardingFeatureList6(collection *ForwardingFeatureList6) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedLength(nil, "ForwardingFeatureList6", "SIZE (1..13)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("encoding ForwardingFeatureList6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERForwardingFeatureList6 decodes a ForwardingFeatureList6 list from BER.
func UnmarshalBERForwardingFeatureList6(data []byte, opts ...ber.DecodeOption) (*ForwardingFeatureList6, error) {
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding ForwardingFeatureList6: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ForwardingFeatureList6", Cause: ber.ErrExtraData}
	}
	var result []ForwardingFeature6
	offset := 0
	for offset < len(content) {
		var elem ForwardingFeature6
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
	if len(result) < 1 || len(result) > 13 {
		if constraintErr := ber.CheckDecodedLength(opts, "ForwardingFeatureList6", "SIZE (1..13)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &ForwardingFeatureList6{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERForwardingFeatureList6(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes ForwardingFeature6 to BER format.
func (v *ForwardingFeature6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingFeature6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *ForwardingFeature6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, fmt.Errorf("encoding forwardedToNumber: %w", encodeErr_enc_forwardedtonumber)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, fmt.Errorf("encoding forwardedToNumber: %w", tagErr_enc_forwardedtonumber)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(opts, "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, fmt.Errorf("encoding forwardedToSubaddress: %w", encodeErr_enc_forwardedtosubaddress)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, fmt.Errorf("encoding forwardedToSubaddress: %w", tagErr_enc_forwardedtosubaddress)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardingoptions, encodeErr_enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		if encodeErr_enc_forwardingoptions != nil {
			return nil, fmt.Errorf("encoding forwardingOptions: %w", encodeErr_enc_forwardingoptions)
		}
		retagged_enc_forwardingoptions, tagErr_enc_forwardingoptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardingoptions)
		if tagErr_enc_forwardingoptions != nil {
			return nil, fmt.Errorf("encoding forwardingOptions: %w", tagErr_enc_forwardingoptions)
		}
		enc_forwardingoptions = retagged_enc_forwardingoptions
		children = append(children, enc_forwardingoptions...)
	}
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := ber.CheckEncodedValue(opts, "noReplyConditionTime", "(5..30)", fmt.Sprint(int64(*v.NoReplyConditionTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		retagged_enc_noreplyconditiontime, tagErr_enc_noreplyconditiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_noreplyconditiontime)
		if tagErr_enc_noreplyconditiontime != nil {
			return nil, fmt.Errorf("encoding noReplyConditionTime: %w", tagErr_enc_noreplyconditiontime)
		}
		enc_noreplyconditiontime = retagged_enc_noreplyconditiontime
		children = append(children, enc_noreplyconditiontime...)
	}
	if v.LongForwardedToNumber != nil {
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 15 {
			if constraintErr := ber.CheckEncodedLength(opts, "longForwardedToNumber", "SIZE (1..15)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "longForwardedToNumber", "SIZE (1..20)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_longforwardedtonumber, encodeErr_enc_longforwardedtonumber := ber.EncodeOctetString([]byte(*v.LongForwardedToNumber))
		if encodeErr_enc_longforwardedtonumber != nil {
			return nil, fmt.Errorf("encoding longForwardedToNumber: %w", encodeErr_enc_longforwardedtonumber)
		}
		retagged_enc_longforwardedtonumber, tagErr_enc_longforwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_longforwardedtonumber)
		if tagErr_enc_longforwardedtonumber != nil {
			return nil, fmt.Errorf("encoding longForwardedToNumber: %w", tagErr_enc_longforwardedtonumber)
		}
		enc_longforwardedtonumber = retagged_enc_longforwardedtonumber
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes ForwardingFeature6 to DER format.
func (v *ForwardingFeature6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardingFeature6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_forwardedtonumber != nil {
			return nil, fmt.Errorf("encoding forwardedToNumber: %w", encodeErr_enc_forwardedtonumber)
		}
		retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
		if tagErr_enc_forwardedtonumber != nil {
			return nil, fmt.Errorf("encoding forwardedToNumber: %w", tagErr_enc_forwardedtonumber)
		}
		enc_forwardedtonumber = retagged_enc_forwardedtonumber
		children = append(children, enc_forwardedtonumber...)
	}
	if v.ForwardedToSubaddress != nil {
		if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(nil, "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardedtosubaddress, encodeErr_enc_forwardedtosubaddress := ber.EncodeOctetString([]byte(*v.ForwardedToSubaddress))
		if encodeErr_enc_forwardedtosubaddress != nil {
			return nil, fmt.Errorf("encoding forwardedToSubaddress: %w", encodeErr_enc_forwardedtosubaddress)
		}
		retagged_enc_forwardedtosubaddress, tagErr_enc_forwardedtosubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_forwardedtosubaddress)
		if tagErr_enc_forwardedtosubaddress != nil {
			return nil, fmt.Errorf("encoding forwardedToSubaddress: %w", tagErr_enc_forwardedtosubaddress)
		}
		enc_forwardedtosubaddress = retagged_enc_forwardedtosubaddress
		children = append(children, enc_forwardedtosubaddress...)
	}
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_forwardingoptions, encodeErr_enc_forwardingoptions := ber.EncodeOctetString([]byte(*v.ForwardingOptions))
		if encodeErr_enc_forwardingoptions != nil {
			return nil, fmt.Errorf("encoding forwardingOptions: %w", encodeErr_enc_forwardingoptions)
		}
		retagged_enc_forwardingoptions, tagErr_enc_forwardingoptions := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_forwardingoptions)
		if tagErr_enc_forwardingoptions != nil {
			return nil, fmt.Errorf("encoding forwardingOptions: %w", tagErr_enc_forwardingoptions)
		}
		enc_forwardingoptions = retagged_enc_forwardingoptions
		children = append(children, enc_forwardingoptions...)
	}
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := ber.CheckEncodedValue(nil, "noReplyConditionTime", "(5..30)", fmt.Sprint(int64(*v.NoReplyConditionTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		retagged_enc_noreplyconditiontime, tagErr_enc_noreplyconditiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_noreplyconditiontime)
		if tagErr_enc_noreplyconditiontime != nil {
			return nil, fmt.Errorf("encoding noReplyConditionTime: %w", tagErr_enc_noreplyconditiontime)
		}
		enc_noreplyconditiontime = retagged_enc_noreplyconditiontime
		children = append(children, enc_noreplyconditiontime...)
	}
	if v.LongForwardedToNumber != nil {
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 15 {
			if constraintErr := ber.CheckEncodedLength(nil, "longForwardedToNumber", "SIZE (1..15)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "longForwardedToNumber", "SIZE (1..20)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_longforwardedtonumber, encodeErr_enc_longforwardedtonumber := ber.EncodeOctetString([]byte(*v.LongForwardedToNumber))
		if encodeErr_enc_longforwardedtonumber != nil {
			return nil, fmt.Errorf("encoding longForwardedToNumber: %w", encodeErr_enc_longforwardedtonumber)
		}
		retagged_enc_longforwardedtonumber, tagErr_enc_longforwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_longforwardedtonumber)
		if tagErr_enc_longforwardedtonumber != nil {
			return nil, fmt.Errorf("encoding longForwardedToNumber: %w", tagErr_enc_longforwardedtonumber)
		}
		enc_longforwardedtonumber = retagged_enc_longforwardedtonumber
		children = append(children, enc_longforwardedtonumber...)
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
		return nil, fmt.Errorf("encoding ForwardingFeature6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingFeature6 from BER/DER format.
func (v *ForwardingFeature6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: ForwardingFeature6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = ForwardingFeature6{}
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
		return fmt.Errorf("decoding ForwardingFeature6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingFeature6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode6)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode6
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicservice")...); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(
					content[offset:]) {
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
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding ss-Status: %w", octetErr)
				}
				tmp_ssstatus := SSStatus6(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
				decodedTag_forwardedtonumber, n_forwardedtonumber, rawVal_forwardedtonumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding forwardedToNumber: %w", err)
				}
				if decodedTag_forwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_forwardedtonumber.Number != 5 {
					return fmt.Errorf("decoding forwardedToNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtonumber)
				}
				decVal_forwardedtonumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtonumber.Constructed, rawVal_forwardedtonumber, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding forwardedToNumber: %w", octetErr)
				}
				tmp_forwardedtonumber := ISDNAddressString6(decVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				if offset < 0 || offset >
					len(content) || n_forwardedtonumber < 0 || n_forwardedtonumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtonumber
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
				decodedTag_forwardedtosubaddress, n_forwardedtosubaddress, rawVal_forwardedtosubaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding forwardedToSubaddress: %w", err)
				}
				if decodedTag_forwardedtosubaddress.Class != tag.ClassContextSpecific || decodedTag_forwardedtosubaddress.Number != 8 {
					return fmt.Errorf("decoding forwardedToSubaddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtosubaddress)
				}
				decVal_forwardedtosubaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtosubaddress.Constructed, rawVal_forwardedtosubaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding forwardedToSubaddress: %w", octetErr)
				}
				tmp_forwardedtosubaddress := ISDNSubaddressString6(decVal_forwardedtosubaddress)
				v.ForwardedToSubaddress = &tmp_forwardedtosubaddress
				if offset < 0 || offset >
					len(content) || n_forwardedtosubaddress < 0 || n_forwardedtosubaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtosubaddress
				if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
					if constraintErr := ber.CheckDecodedLength(opts, "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
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
				decodedTag_forwardingoptions, n_forwardingoptions, rawVal_forwardingoptions, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding forwardingOptions: %w", err)
				}
				if decodedTag_forwardingoptions.Class != tag.ClassContextSpecific || decodedTag_forwardingoptions.Number != 6 {
					return fmt.Errorf("decoding forwardingOptions: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardingoptions)
				}
				decVal_forwardingoptions, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardingoptions.Constructed, rawVal_forwardingoptions, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding forwardingOptions: %w", octetErr)
				}
				tmp_forwardingoptions := ForwardingOptions6(decVal_forwardingoptions)
				v.ForwardingOptions = &tmp_forwardingoptions
				if offset < 0 || offset >
					len(content) || n_forwardingoptions < 0 || n_forwardingoptions >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardingoptions
				if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
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
				decodedTag_noreplyconditiontime, n_noreplyconditiontime, rawVal_noreplyconditiontime, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_noreplyconditiontime := NoReplyConditionTime6(decVal_noreplyconditiontime)
				v.NoReplyConditionTime = &tmp_noreplyconditiontime
				if offset < 0 || offset >
					len(content) || n_noreplyconditiontime < 0 || n_noreplyconditiontime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_noreplyconditiontime
				if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
					if constraintErr := ber.CheckDecodedValue(opts, "noReplyConditionTime", "(5..30)", fmt.Sprint(int64(*v.NoReplyConditionTime))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode longForwardedToNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 {
				decodedTag_longforwardedtonumber, n_longforwardedtonumber, rawVal_longforwardedtonumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding longForwardedToNumber: %w", err)
				}
				if decodedTag_longforwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_longforwardedtonumber.Number != 9 {
					return fmt.Errorf("decoding longForwardedToNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longforwardedtonumber)
				}
				decVal_longforwardedtonumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_longforwardedtonumber.Constructed, rawVal_longforwardedtonumber, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding longForwardedToNumber: %w", octetErr)
				}
				tmp_longforwardedtonumber := FTNAddressString6(decVal_longforwardedtonumber)
				v.LongForwardedToNumber = &tmp_longforwardedtonumber
				if offset < 0 || offset >
					len(content) || n_longforwardedtonumber < 0 || n_longforwardedtonumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_longforwardedtonumber
				if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 15 {
					if constraintErr := ber.CheckDecodedLength(opts, "longForwardedToNumber", "SIZE (1..15)", len(*v.LongForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "longForwardedToNumber", "SIZE (1..20)", len(*v.LongForwardedToNumber)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingFeature6", Cause: extErr_}
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

// MarshalBER encodes CallBarringInfo6 to BER format.
func (v *CallBarringInfo6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CallBarringInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CallBarringInfo6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
		}
		children = append(children, enc_sscode...)
	}
	if v.CallBarringFeatureList == nil {
		return nil, fmt.Errorf("encoding callBarringFeatureList: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.CallBarringFeatureList).Values) < 1 || len((v.CallBarringFeatureList).Values) > 13 {
		if constraintErr := ber.CheckEncodedLength(opts, "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callbarringfeaturelist, err := MarshalBERCallBarringFeatureList6(v.CallBarringFeatureList, opts...)
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes CallBarringInfo6 to DER format.
func (v *CallBarringInfo6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CallBarringInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
		}
		children = append(children, enc_sscode...)
	}
	if v.CallBarringFeatureList == nil {
		return nil, fmt.Errorf("encoding callBarringFeatureList: %w: required collection is nil", ber.ErrInvalidValue)
	}
	if len((v.CallBarringFeatureList).Values) < 1 || len((v.CallBarringFeatureList).Values) > 13 {
		if constraintErr := ber.CheckEncodedLength(nil, "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callbarringfeaturelist, err := MarshalDERCallBarringFeatureList6(v.CallBarringFeatureList)
	if err != nil {
		return nil, fmt.Errorf("encoding callBarringFeatureList: %w", err)
	}
	children = append(children, enc_callbarringfeaturelist...)
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
		return nil, fmt.Errorf("encoding CallBarringInfo6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CallBarringInfo6 from BER/DER format.
func (v *CallBarringInfo6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CallBarringInfo6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CallBarringInfo6{}
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
		return fmt.Errorf("decoding CallBarringInfo6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarringInfo6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				tmp_sscode := SSCode6(val_sscode)
				v.SsCode = &tmp_sscode
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode callBarringFeatureList
	if offset >= len(content) {
		return fmt.Errorf("missing required field callBarringFeatureList")
	}
	v.CallBarringFeatureListIndef_ = false
	// Decode nested SEQUENCE_OF (CallBarringFeatureList6)
	_, n_callbarringfeaturelist, _, tlvErr_callbarringfeaturelist := ber.DecodeTLV(content[offset:], opts...)
	if tlvErr_callbarringfeaturelist != nil {
		return fmt.Errorf("decoding callBarringFeatureList: %w", tlvErr_callbarringfeaturelist)
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
			v.CallBarringFeatureListIndef_ = true
		}
	}
	dec_callbarringfeaturelist, unmErr := UnmarshalBERCallBarringFeatureList6(tlv_callbarringfeaturelist, ber.ChildDecodeOptions(opts, "callBarringFeatureList")...)
	if unmErr != nil {
		return fmt.Errorf("decoding callBarringFeatureList: %w", unmErr)
	}
	v.CallBarringFeatureList = dec_callbarringfeaturelist
	if offset < 0 || offset >
		len(content) || n_callbarringfeaturelist < 0 || n_callbarringfeaturelist >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_callbarringfeaturelist
	if len((v.CallBarringFeatureList).Values) < 1 || len((v.CallBarringFeatureList).Values) > 13 {
		if constraintErr := ber.CheckDecodedLength(opts, "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CallBarringInfo6", Cause: extErr_}
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

// MarshalBERCallBarringFeatureList6 encodes a CallBarringFeatureList6 list to BER.
func MarshalBERCallBarringFeatureList6(collection *CallBarringFeatureList6, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERCallBarringFeatureList6(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERCallBarringFeatureList6(collection *CallBarringFeatureList6, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedLength(opts, "CallBarringFeatureList6", "SIZE (1..13)", len(list)); constraintErr != nil {
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

// MarshalDERCallBarringFeatureList6 encodes a CallBarringFeatureList6 list to DER.
func MarshalDERCallBarringFeatureList6(collection *CallBarringFeatureList6) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedLength(nil, "CallBarringFeatureList6", "SIZE (1..13)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("encoding CallBarringFeatureList6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERCallBarringFeatureList6 decodes a CallBarringFeatureList6 list from BER.
func UnmarshalBERCallBarringFeatureList6(data []byte, opts ...ber.DecodeOption) (*CallBarringFeatureList6, error) {
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding CallBarringFeatureList6: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CallBarringFeatureList6", Cause: ber.ErrExtraData}
	}
	var result []CallBarringFeature6
	offset := 0
	for offset < len(content) {
		var elem CallBarringFeature6
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
	if len(result) < 1 || len(result) > 13 {
		if constraintErr := ber.CheckDecodedLength(opts, "CallBarringFeatureList6", "SIZE (1..13)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &CallBarringFeatureList6{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERCallBarringFeatureList6(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes CallBarringFeature6 to BER format.
func (v *CallBarringFeature6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CallBarringFeature6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CallBarringFeature6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
		}
		enc_ssstatus = retagged_enc_ssstatus
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes CallBarringFeature6 to DER format.
func (v *CallBarringFeature6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CallBarringFeature6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
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
		return nil, fmt.Errorf("encoding CallBarringFeature6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CallBarringFeature6 from BER/DER format.
func (v *CallBarringFeature6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CallBarringFeature6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CallBarringFeature6{}
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
		return fmt.Errorf("decoding CallBarringFeature6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarringFeature6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode6)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode6
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicservice")...); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
				}
				v.BasicService = &dec_basicservice
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
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
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding ss-Status: %w", octetErr)
				}
				tmp_ssstatus := SSStatus6(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "CallBarringFeature6", Cause: extErr_}
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

// MarshalBER encodes SSData6 to BER format.
func (v *SSData6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSData6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSData6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
		}
		children = append(children, enc_sscode...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	if v.SsSubscriptionOption != nil {
		enc_sssubscriptionoption, err := v.SsSubscriptionOption.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding ss-SubscriptionOption: %w", err)
		}
		children = append(children, enc_sssubscriptionoption...)
	}
	if v.BasicServiceGroupList != nil {
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(opts, "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservicegrouplist, err := MarshalBERBasicServiceGroupList6(v.BasicServiceGroupList, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList: %w", err)
		}
		children = append(children, enc_basicservicegrouplist...)
	}
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := ber.CheckEncodedValue(opts, "defaultPriority", "(0..15)", fmt.Sprint(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		children = append(children, enc_defaultpriority...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := ber.CheckEncodedValue(opts, "nbrUser", "(1..7)", fmt.Sprint(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, fmt.Errorf("encoding nbrUser: %w", tagErr_enc_nbruser)
		}
		enc_nbruser = retagged_enc_nbruser
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SSData6 to DER format.
func (v *SSData6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSData6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
		}
		children = append(children, enc_sscode...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	if v.SsSubscriptionOption != nil {
		enc_sssubscriptionoption, err := v.SsSubscriptionOption.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ss-SubscriptionOption: %w", err)
		}
		children = append(children, enc_sssubscriptionoption...)
	}
	if v.BasicServiceGroupList != nil {
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(nil, "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservicegrouplist, err := MarshalDERBasicServiceGroupList6(v.BasicServiceGroupList)
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList: %w", err)
		}
		children = append(children, enc_basicservicegrouplist...)
	}
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := ber.CheckEncodedValue(nil, "defaultPriority", "(0..15)", fmt.Sprint(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		children = append(children, enc_defaultpriority...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := ber.CheckEncodedValue(nil, "nbrUser", "(1..7)", fmt.Sprint(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, fmt.Errorf("encoding nbrUser: %w", tagErr_enc_nbruser)
		}
		enc_nbruser = retagged_enc_nbruser
		children = append(children, enc_nbruser...)
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
		return nil, fmt.Errorf("encoding SSData6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSData6 from BER/DER format.
func (v *SSData6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSData6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSData6{}
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
		return fmt.Errorf("decoding SSData6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSData6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ss-Code: %w", err)
				}
				tmp_sscode := SSCode6(val_sscode)
				v.SsCode = &tmp_sscode
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 4 {
					return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding ss-Status: %w", octetErr)
				}
				tmp_ssstatus := SSStatus6(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
				// Decode nested CHOICE (SSSubscriptionOption6)
				_, n_sssubscriptionoption, _, tlvErr_sssubscriptionoption := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_sssubscriptionoption != nil {
					return fmt.Errorf("decoding ss-SubscriptionOption: %w", tlvErr_sssubscriptionoption)
				}
				var dec_sssubscriptionoption SSSubscriptionOption6
				if offset < 0 || offset >
					len(content) || n_sssubscriptionoption < 0 || n_sssubscriptionoption >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_sssubscriptionoption.UnmarshalBER(content[offset:offset+n_sssubscriptionoption], ber.ChildDecodeOptions(opts, "sssubscriptionoption")...); unmErr != nil {
					return fmt.Errorf("decoding ss-SubscriptionOption: %w", unmErr)
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
	v.BasicServiceGroupListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE_OF (BasicServiceGroupList6)
				_, n_basicservicegrouplist, _, tlvErr_basicservicegrouplist := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservicegrouplist != nil {
					return fmt.Errorf("decoding basicServiceGroupList: %w", tlvErr_basicservicegrouplist)
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
						v.BasicServiceGroupListIndef_ = true
					}
				}
				dec_basicservicegrouplist, unmErr := UnmarshalBERBasicServiceGroupList6(tlv_basicservicegrouplist, ber.ChildDecodeOptions(opts, "basicServiceGroupList")...)
				if unmErr != nil {
					return fmt.Errorf("decoding basicServiceGroupList: %w", unmErr)
				}
				v.BasicServiceGroupList = dec_basicservicegrouplist
				if offset < 0 || offset >
					len(content) || n_basicservicegrouplist < 0 || n_basicservicegrouplist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservicegrouplist
				if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
					if constraintErr := ber.CheckDecodedLength(opts, "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode defaultPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 2 {
				val_defaultpriority, n, err := ber.DecodeInteger(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding defaultPriority: %w", err)
				}
				tmp_defaultpriority := EMLPPPriority6(val_defaultpriority)
				v.DefaultPriority = &tmp_defaultpriority
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
					if constraintErr := ber.CheckDecodedValue(opts, "defaultPriority", "(0..15)", fmt.Sprint(int64(*v.DefaultPriority))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode nbrUser
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_nbruser := MCBearers6(decVal_nbruser)
				v.NbrUser = &tmp_nbruser
				if offset < 0 || offset >
					len(content) || n_nbruser < 0 || n_nbruser > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nbruser
				if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
					if constraintErr := ber.CheckDecodedValue(opts, "nbrUser", "(1..7)", fmt.Sprint(int64(*v.NbrUser))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSData6", Cause: extErr_}
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

// MarshalBER encodes SSSubscriptionOption6 to BER format.
func (v *SSSubscriptionOption6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSubscriptionOption6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSSubscriptionOption6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SSSubscriptionOption6ChoiceCliRestrictionOption:
		if v.CliRestrictionOption == nil {
			return nil, fmt.Errorf("%w: choice SSSubscriptionOption6: cliRestrictionOption is nil", ber.ErrInvalidValue)
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
			if constraintErr := ber.CheckEncodedValue(opts, "cliRestrictionOption", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding cliRestrictionOption: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SSSubscriptionOption6ChoiceOverrideCategory:
		if v.OverrideCategory == nil {
			return nil, fmt.Errorf("%w: choice SSSubscriptionOption6: overrideCategory is nil", ber.ErrInvalidValue)
		}
		enc_1 := ber.EncodeEnumerated(int64(*v.OverrideCategory))
		if int64(*v.OverrideCategory) != 0 && int64(*v.OverrideCategory) != 1 {
			if constraintErr := ber.CheckEncodedValue(opts, "overrideCategory", "ENUMERATED {0, 1}", fmt.Sprint(int64(*v.OverrideCategory))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding overrideCategory: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSSubscriptionOption6", v.Choice)
	}
}

// MarshalDER encodes SSSubscriptionOption6 to DER format.
func (v *SSSubscriptionOption6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSubscriptionOption6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSSubscriptionOption6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSSubscriptionOption6 from BER/DER format.
func (v *SSSubscriptionOption6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSSubscriptionOption6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
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
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSSubscriptionOption6{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSSubscriptionOption6 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSSubscriptionOption6: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding SSSubscriptionOption6 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSubscriptionOption6", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOption6ChoiceCliRestrictionOption
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding cliRestrictionOption: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeEnumeratedValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding cliRestrictionOption: %w", intErr)
		}
		tmp := CliRestrictionOption6(decVal)
		v.CliRestrictionOption = &tmp
		if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
			if constraintErr := ber.CheckDecodedValue(opts, "cliRestrictionOption", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOption6ChoiceOverrideCategory
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding overrideCategory: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeEnumeratedValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding overrideCategory: %w", intErr)
		}
		tmp := OverrideCategory6(decVal)
		v.OverrideCategory = &tmp
		if int64(*v.OverrideCategory) != 0 && int64(*v.OverrideCategory) != 1 {
			if constraintErr := ber.CheckDecodedValue(opts, "overrideCategory", "ENUMERATED {0, 1}", fmt.Sprint(int64(*v.OverrideCategory))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for SSSubscriptionOption6 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SSForBSCode6 to BER format.
func (v *SSForBSCode6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSForBSCode6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSForBSCode6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	children = append(children, enc_sscode...)
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, fmt.Errorf("encoding longFTN-Supported: %w", tagErr_enc_longftnsupported)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SSForBSCode6 to DER format.
func (v *SSForBSCode6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSForBSCode6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	children = append(children, enc_sscode...)
	if v.BasicService != nil {
		enc_basicservice, err := v.BasicService.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicService: %w", err)
		}
		children = append(children, enc_basicservice...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, fmt.Errorf("encoding longFTN-Supported: %w", tagErr_enc_longftnsupported)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
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
		return nil, fmt.Errorf("encoding SSForBSCode6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSForBSCode6 from BER/DER format.
func (v *SSForBSCode6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSForBSCode6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSForBSCode6{}
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
		return fmt.Errorf("decoding SSForBSCode6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSForBSCode6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	v.SsCode = SSCode6(val_sscode)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode6)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode6
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicservice")...); unmErr != nil {
					return fmt.Errorf("decoding basicService: %w", unmErr)
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
	// Decode longFTN-Supported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_longftnsupported, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:], opts...)
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
				if offset < 0 || offset >
					len(content) || n_longftnsupported < 0 || n_longftnsupported >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_longftnsupported
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSForBSCode6", Cause: extErr_}
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

// MarshalBER encodes GenericServiceInfo6 to BER format.
func (v *GenericServiceInfo6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: GenericServiceInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *GenericServiceInfo6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
	}
	children = append(children, enc_ssstatus...)
	if v.CliRestrictionOption != nil {
		if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
			if constraintErr := ber.CheckEncodedValue(opts, "cliRestrictionOption", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_clirestrictionoption := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		children = append(children, enc_clirestrictionoption...)
	}
	if v.MaximumEntitledPriority != nil {
		if !(int64(*v.MaximumEntitledPriority) >= 0 && int64(*v.MaximumEntitledPriority) <= 15) {
			if constraintErr := ber.CheckEncodedValue(opts, "maximumEntitledPriority", "(0..15)", fmt.Sprint(int64(*v.MaximumEntitledPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximumentitledpriority := ber.EncodeInteger(int64(*v.MaximumEntitledPriority))
		retagged_enc_maximumentitledpriority, tagErr_enc_maximumentitledpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_maximumentitledpriority)
		if tagErr_enc_maximumentitledpriority != nil {
			return nil, fmt.Errorf("encoding maximumEntitledPriority: %w", tagErr_enc_maximumentitledpriority)
		}
		enc_maximumentitledpriority = retagged_enc_maximumentitledpriority
		children = append(children, enc_maximumentitledpriority...)
	}
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := ber.CheckEncodedValue(opts, "defaultPriority", "(0..15)", fmt.Sprint(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		retagged_enc_defaultpriority, tagErr_enc_defaultpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_defaultpriority)
		if tagErr_enc_defaultpriority != nil {
			return nil, fmt.Errorf("encoding defaultPriority: %w", tagErr_enc_defaultpriority)
		}
		enc_defaultpriority = retagged_enc_defaultpriority
		children = append(children, enc_defaultpriority...)
	}
	if v.CcbsFeatureList != nil {
		if len((v.CcbsFeatureList).Values) < 1 || len((v.CcbsFeatureList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(opts, "ccbs-FeatureList", "SIZE (1..5)", len((v.CcbsFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsfeaturelist, err := MarshalBERCCBSFeatureList6(v.CcbsFeatureList, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-FeatureList: %w", err)
		}
		if v.CcbsFeatureListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_ccbsfeaturelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_ccbsfeaturelist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding ccbs-FeatureList: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_ccbsfeaturelist, tagErr_enc_ccbsfeaturelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsfeaturelist)
			if tagErr_enc_ccbsfeaturelist != nil {
				return nil, fmt.Errorf("encoding ccbs-FeatureList: %w", tagErr_enc_ccbsfeaturelist)
			}
			enc_ccbsfeaturelist = retagged_enc_ccbsfeaturelist
		}
		children = append(children, enc_ccbsfeaturelist...)
	}
	if v.NbrSB != nil {
		if !(int64(*v.NbrSB) >= 2 && int64(*v.NbrSB) <= 7) {
			if constraintErr := ber.CheckEncodedValue(opts, "nbrSB", "(2..7)", fmt.Sprint(int64(*v.NbrSB))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbrsb := ber.EncodeInteger(int64(*v.NbrSB))
		retagged_enc_nbrsb, tagErr_enc_nbrsb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_nbrsb)
		if tagErr_enc_nbrsb != nil {
			return nil, fmt.Errorf("encoding nbrSB: %w", tagErr_enc_nbrsb)
		}
		enc_nbrsb = retagged_enc_nbrsb
		children = append(children, enc_nbrsb...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := ber.CheckEncodedValue(opts, "nbrUser", "(1..7)", fmt.Sprint(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, fmt.Errorf("encoding nbrUser: %w", tagErr_enc_nbruser)
		}
		enc_nbruser = retagged_enc_nbruser
		children = append(children, enc_nbruser...)
	}
	if v.NbrSN != nil {
		if !(int64(*v.NbrSN) >= 1 && int64(*v.NbrSN) <= 7) {
			if constraintErr := ber.CheckEncodedValue(opts, "nbrSN", "(1..7)", fmt.Sprint(int64(*v.NbrSN))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbrsn := ber.EncodeInteger(int64(*v.NbrSN))
		retagged_enc_nbrsn, tagErr_enc_nbrsn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_nbrsn)
		if tagErr_enc_nbrsn != nil {
			return nil, fmt.Errorf("encoding nbrSN: %w", tagErr_enc_nbrsn)
		}
		enc_nbrsn = retagged_enc_nbrsn
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes GenericServiceInfo6 to DER format.
func (v *GenericServiceInfo6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: GenericServiceInfo6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
	}
	children = append(children, enc_ssstatus...)
	if v.CliRestrictionOption != nil {
		if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
			if constraintErr := ber.CheckEncodedValue(nil, "cliRestrictionOption", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_clirestrictionoption := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		children = append(children, enc_clirestrictionoption...)
	}
	if v.MaximumEntitledPriority != nil {
		if !(int64(*v.MaximumEntitledPriority) >= 0 && int64(*v.MaximumEntitledPriority) <= 15) {
			if constraintErr := ber.CheckEncodedValue(nil, "maximumEntitledPriority", "(0..15)", fmt.Sprint(int64(*v.MaximumEntitledPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximumentitledpriority := ber.EncodeInteger(int64(*v.MaximumEntitledPriority))
		retagged_enc_maximumentitledpriority, tagErr_enc_maximumentitledpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_maximumentitledpriority)
		if tagErr_enc_maximumentitledpriority != nil {
			return nil, fmt.Errorf("encoding maximumEntitledPriority: %w", tagErr_enc_maximumentitledpriority)
		}
		enc_maximumentitledpriority = retagged_enc_maximumentitledpriority
		children = append(children, enc_maximumentitledpriority...)
	}
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := ber.CheckEncodedValue(nil, "defaultPriority", "(0..15)", fmt.Sprint(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		retagged_enc_defaultpriority, tagErr_enc_defaultpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_defaultpriority)
		if tagErr_enc_defaultpriority != nil {
			return nil, fmt.Errorf("encoding defaultPriority: %w", tagErr_enc_defaultpriority)
		}
		enc_defaultpriority = retagged_enc_defaultpriority
		children = append(children, enc_defaultpriority...)
	}
	if v.CcbsFeatureList != nil {
		if len((v.CcbsFeatureList).Values) < 1 || len((v.CcbsFeatureList).Values) > 5 {
			if constraintErr := ber.CheckEncodedLength(nil, "ccbs-FeatureList", "SIZE (1..5)", len((v.CcbsFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsfeaturelist, err := MarshalDERCCBSFeatureList6(v.CcbsFeatureList)
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-FeatureList: %w", err)
		}
		retagged_enc_ccbsfeaturelist, tagErr_enc_ccbsfeaturelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsfeaturelist)
		if tagErr_enc_ccbsfeaturelist != nil {
			return nil, fmt.Errorf("encoding ccbs-FeatureList: %w", tagErr_enc_ccbsfeaturelist)
		}
		enc_ccbsfeaturelist = retagged_enc_ccbsfeaturelist
		children = append(children, enc_ccbsfeaturelist...)
	}
	if v.NbrSB != nil {
		if !(int64(*v.NbrSB) >= 2 && int64(*v.NbrSB) <= 7) {
			if constraintErr := ber.CheckEncodedValue(nil, "nbrSB", "(2..7)", fmt.Sprint(int64(*v.NbrSB))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbrsb := ber.EncodeInteger(int64(*v.NbrSB))
		retagged_enc_nbrsb, tagErr_enc_nbrsb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_nbrsb)
		if tagErr_enc_nbrsb != nil {
			return nil, fmt.Errorf("encoding nbrSB: %w", tagErr_enc_nbrsb)
		}
		enc_nbrsb = retagged_enc_nbrsb
		children = append(children, enc_nbrsb...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := ber.CheckEncodedValue(nil, "nbrUser", "(1..7)", fmt.Sprint(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, fmt.Errorf("encoding nbrUser: %w", tagErr_enc_nbruser)
		}
		enc_nbruser = retagged_enc_nbruser
		children = append(children, enc_nbruser...)
	}
	if v.NbrSN != nil {
		if !(int64(*v.NbrSN) >= 1 && int64(*v.NbrSN) <= 7) {
			if constraintErr := ber.CheckEncodedValue(nil, "nbrSN", "(1..7)", fmt.Sprint(int64(*v.NbrSN))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbrsn := ber.EncodeInteger(int64(*v.NbrSN))
		retagged_enc_nbrsn, tagErr_enc_nbrsn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_nbrsn)
		if tagErr_enc_nbrsn != nil {
			return nil, fmt.Errorf("encoding nbrSN: %w", tagErr_enc_nbrsn)
		}
		enc_nbrsn = retagged_enc_nbrsn
		children = append(children, enc_nbrsn...)
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
		return nil, fmt.Errorf("encoding GenericServiceInfo6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes GenericServiceInfo6 from BER/DER format.
func (v *GenericServiceInfo6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: GenericServiceInfo6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = GenericServiceInfo6{}
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
		return fmt.Errorf("decoding GenericServiceInfo6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GenericServiceInfo6", Cause: ber.ErrExtraData}
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
	v.SsStatus = SSStatus6(val_ssstatus)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode cliRestrictionOption
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 10 {
				val_clirestrictionoption, n, err := ber.DecodeEnumerated(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding cliRestrictionOption: %w", err)
				}
				tmp_clirestrictionoption := CliRestrictionOption6(val_clirestrictionoption)
				v.CliRestrictionOption = &tmp_clirestrictionoption
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
					if constraintErr := ber.CheckDecodedValue(opts, "cliRestrictionOption", "ENUMERATED {0, 1, 2}", fmt.Sprint(int64(*v.CliRestrictionOption))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode maximumEntitledPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_maximumentitledpriority, n_maximumentitledpriority, rawVal_maximumentitledpriority, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_maximumentitledpriority := EMLPPPriority6(decVal_maximumentitledpriority)
				v.MaximumEntitledPriority = &tmp_maximumentitledpriority
				if offset < 0 || offset >
					len(content) || n_maximumentitledpriority < 0 || n_maximumentitledpriority >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_maximumentitledpriority
				if !(int64(*v.MaximumEntitledPriority) >= 0 && int64(*v.MaximumEntitledPriority) <= 15) {
					if constraintErr := ber.CheckDecodedValue(opts, "maximumEntitledPriority", "(0..15)", fmt.Sprint(int64(*v.MaximumEntitledPriority))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode defaultPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_defaultpriority, n_defaultpriority, rawVal_defaultpriority, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_defaultpriority := EMLPPPriority6(decVal_defaultpriority)
				v.DefaultPriority = &tmp_defaultpriority
				if offset < 0 || offset >
					len(content) || n_defaultpriority < 0 || n_defaultpriority >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_defaultpriority
				if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
					if constraintErr := ber.CheckDecodedValue(opts, "defaultPriority", "(0..15)", fmt.Sprint(int64(*v.DefaultPriority))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ccbs-FeatureList
	v.CcbsFeatureListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_ccbsfeaturelist, n_ccbsfeaturelist, rawVal_ccbsfeaturelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ccbs-FeatureList: %w", err)
				}
				if decodedTag_ccbsfeaturelist.Class != tag.ClassContextSpecific || decodedTag_ccbsfeaturelist.Number != 2 || decodedTag_ccbsfeaturelist.Constructed != true {
					return fmt.Errorf("decoding ccbs-FeatureList: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsfeaturelist)
				}
				reconstructed_ccbsfeaturelist, reconstructionErr_ccbsfeaturelist := ber.EncodeSequence(rawVal_ccbsfeaturelist)
				if reconstructionErr_ccbsfeaturelist != nil {
					return fmt.Errorf("decoding ccbs-FeatureList: %w", reconstructionErr_ccbsfeaturelist)
				}
				dec_ccbsfeaturelist, unmErr := UnmarshalBERCCBSFeatureList6(reconstructed_ccbsfeaturelist, ber.ChildDecodeOptions(opts, "ccbs-FeatureList")...)
				if unmErr != nil {
					return fmt.Errorf("decoding ccbs-FeatureList: %w", unmErr)
				}
				v.CcbsFeatureList = dec_ccbsfeaturelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.CcbsFeatureListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_ccbsfeaturelist < 0 || n_ccbsfeaturelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsfeaturelist
				if len((v.CcbsFeatureList).Values) < 1 || len((v.CcbsFeatureList).Values) > 5 {
					if constraintErr := ber.CheckDecodedLength(opts, "ccbs-FeatureList", "SIZE (1..5)", len((v.CcbsFeatureList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode nbrSB
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_nbrsb, n_nbrsb, rawVal_nbrsb, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_nbrsb := MaxMCBearers6(decVal_nbrsb)
				v.NbrSB = &tmp_nbrsb
				if offset < 0 || offset >
					len(content) || n_nbrsb < 0 || n_nbrsb > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nbrsb
				if !(int64(*v.NbrSB) >= 2 && int64(*v.NbrSB) <= 7) {
					if constraintErr := ber.CheckDecodedValue(opts, "nbrSB", "(2..7)", fmt.Sprint(int64(*v.NbrSB))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode nbrUser
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_nbruser := MCBearers6(decVal_nbruser)
				v.NbrUser = &tmp_nbruser
				if offset < 0 || offset >
					len(content) || n_nbruser < 0 || n_nbruser > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nbruser
				if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
					if constraintErr := ber.CheckDecodedValue(opts, "nbrUser", "(1..7)", fmt.Sprint(int64(*v.NbrUser))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode nbrSN
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_nbrsn, n_nbrsn, rawVal_nbrsn, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_nbrsn := MCBearers6(decVal_nbrsn)
				v.NbrSN = &tmp_nbrsn
				if offset < 0 || offset >
					len(content) || n_nbrsn < 0 || n_nbrsn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nbrsn
				if !(int64(*v.NbrSN) >= 1 && int64(*v.NbrSN) <= 7) {
					if constraintErr := ber.CheckDecodedValue(opts, "nbrSN", "(1..7)", fmt.Sprint(int64(*v.NbrSN))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "GenericServiceInfo6", Cause: extErr_}
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

// MarshalBERCCBSFeatureList6 encodes a CCBSFeatureList6 list to BER.
func MarshalBERCCBSFeatureList6(collection *CCBSFeatureList6, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERCCBSFeatureList6(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERCCBSFeatureList6(collection *CCBSFeatureList6, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedLength(opts, "CCBSFeatureList6", "SIZE (1..5)", len(list)); constraintErr != nil {
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

// MarshalDERCCBSFeatureList6 encodes a CCBSFeatureList6 list to DER.
func MarshalDERCCBSFeatureList6(collection *CCBSFeatureList6) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := ber.CheckEncodedLength(nil, "CCBSFeatureList6", "SIZE (1..5)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("encoding CCBSFeatureList6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERCCBSFeatureList6 decodes a CCBSFeatureList6 list from BER.
func UnmarshalBERCCBSFeatureList6(data []byte, opts ...ber.DecodeOption) (*CCBSFeatureList6, error) {
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding CCBSFeatureList6: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CCBSFeatureList6", Cause: ber.ErrExtraData}
	}
	var result []CCBSFeature6
	offset := 0
	for offset < len(content) {
		var elem CCBSFeature6
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
	if len(result) < 1 || len(result) > 5 {
		if constraintErr := ber.CheckDecodedLength(opts, "CCBSFeatureList6", "SIZE (1..5)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &CCBSFeatureList6{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERCCBSFeatureList6(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes CCBSFeature6 to BER format.
func (v *CCBSFeature6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CCBSFeature6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CCBSFeature6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CcbsIndex != nil {
		if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
			if constraintErr := ber.CheckEncodedValue(opts, "ccbs-Index", "(1..5)", fmt.Sprint(int64(*v.CcbsIndex))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsindex := ber.EncodeInteger(int64(*v.CcbsIndex))
		retagged_enc_ccbsindex, tagErr_enc_ccbsindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsindex)
		if tagErr_enc_ccbsindex != nil {
			return nil, fmt.Errorf("encoding ccbs-Index: %w", tagErr_enc_ccbsindex)
		}
		enc_ccbsindex = retagged_enc_ccbsindex
		children = append(children, enc_ccbsindex...)
	}
	if v.BSubscriberNumber != nil {
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribernumber, encodeErr_enc_bsubscribernumber := ber.EncodeOctetString([]byte(*v.BSubscriberNumber))
		if encodeErr_enc_bsubscribernumber != nil {
			return nil, fmt.Errorf("encoding b-subscriberNumber: %w", encodeErr_enc_bsubscribernumber)
		}
		retagged_enc_bsubscribernumber, tagErr_enc_bsubscribernumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_bsubscribernumber)
		if tagErr_enc_bsubscribernumber != nil {
			return nil, fmt.Errorf("encoding b-subscriberNumber: %w", tagErr_enc_bsubscribernumber)
		}
		enc_bsubscribernumber = retagged_enc_bsubscribernumber
		children = append(children, enc_bsubscribernumber...)
	}
	if v.BSubscriberSubaddress != nil {
		if len(*v.BSubscriberSubaddress) < 1 || len(*v.BSubscriberSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(opts, "b-subscriberSubaddress", "SIZE (1..21)", len(*v.BSubscriberSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribersubaddress, encodeErr_enc_bsubscribersubaddress := ber.EncodeOctetString([]byte(*v.BSubscriberSubaddress))
		if encodeErr_enc_bsubscribersubaddress != nil {
			return nil, fmt.Errorf("encoding b-subscriberSubaddress: %w", encodeErr_enc_bsubscribersubaddress)
		}
		retagged_enc_bsubscribersubaddress, tagErr_enc_bsubscribersubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_bsubscribersubaddress)
		if tagErr_enc_bsubscribersubaddress != nil {
			return nil, fmt.Errorf("encoding b-subscriberSubaddress: %w", tagErr_enc_bsubscribersubaddress)
		}
		enc_bsubscribersubaddress = retagged_enc_bsubscribersubaddress
		children = append(children, enc_bsubscribersubaddress...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroup: %w", err)
		}
		{
			var encodeErr error
			enc_basicservicegroup, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_basicservicegroup)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding basicServiceGroup: %w", encodeErr)
			}
		}
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes CCBSFeature6 to DER format.
func (v *CCBSFeature6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CCBSFeature6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CcbsIndex != nil {
		if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
			if constraintErr := ber.CheckEncodedValue(nil, "ccbs-Index", "(1..5)", fmt.Sprint(int64(*v.CcbsIndex))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsindex := ber.EncodeInteger(int64(*v.CcbsIndex))
		retagged_enc_ccbsindex, tagErr_enc_ccbsindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsindex)
		if tagErr_enc_ccbsindex != nil {
			return nil, fmt.Errorf("encoding ccbs-Index: %w", tagErr_enc_ccbsindex)
		}
		enc_ccbsindex = retagged_enc_ccbsindex
		children = append(children, enc_ccbsindex...)
	}
	if v.BSubscriberNumber != nil {
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribernumber, encodeErr_enc_bsubscribernumber := ber.EncodeOctetString([]byte(*v.BSubscriberNumber))
		if encodeErr_enc_bsubscribernumber != nil {
			return nil, fmt.Errorf("encoding b-subscriberNumber: %w", encodeErr_enc_bsubscribernumber)
		}
		retagged_enc_bsubscribernumber, tagErr_enc_bsubscribernumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_bsubscribernumber)
		if tagErr_enc_bsubscribernumber != nil {
			return nil, fmt.Errorf("encoding b-subscriberNumber: %w", tagErr_enc_bsubscribernumber)
		}
		enc_bsubscribernumber = retagged_enc_bsubscribernumber
		children = append(children, enc_bsubscribernumber...)
	}
	if v.BSubscriberSubaddress != nil {
		if len(*v.BSubscriberSubaddress) < 1 || len(*v.BSubscriberSubaddress) > 21 {
			if constraintErr := ber.CheckEncodedLength(nil, "b-subscriberSubaddress", "SIZE (1..21)", len(*v.BSubscriberSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribersubaddress, encodeErr_enc_bsubscribersubaddress := ber.EncodeOctetString([]byte(*v.BSubscriberSubaddress))
		if encodeErr_enc_bsubscribersubaddress != nil {
			return nil, fmt.Errorf("encoding b-subscriberSubaddress: %w", encodeErr_enc_bsubscribersubaddress)
		}
		retagged_enc_bsubscribersubaddress, tagErr_enc_bsubscribersubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_bsubscribersubaddress)
		if tagErr_enc_bsubscribersubaddress != nil {
			return nil, fmt.Errorf("encoding b-subscriberSubaddress: %w", tagErr_enc_bsubscribersubaddress)
		}
		enc_bsubscribersubaddress = retagged_enc_bsubscribersubaddress
		children = append(children, enc_bsubscribersubaddress...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroup: %w", err)
		}
		{
			var encodeErr error
			enc_basicservicegroup, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_basicservicegroup)
			if encodeErr != nil {
				return nil, fmt.Errorf("encoding basicServiceGroup: %w", encodeErr)
			}
		}
		children = append(children, enc_basicservicegroup...)
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
		return nil, fmt.Errorf("encoding CCBSFeature6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CCBSFeature6 from BER/DER format.
func (v *CCBSFeature6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CCBSFeature6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CCBSFeature6{}
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
		return fmt.Errorf("decoding CCBSFeature6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CCBSFeature6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ccbs-Index
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_ccbsindex, n_ccbsindex, rawVal_ccbsindex, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_ccbsindex := CCBSIndex6(decVal_ccbsindex)
				v.CcbsIndex = &tmp_ccbsindex
				if offset < 0 || offset >
					len(content) || n_ccbsindex < 0 || n_ccbsindex > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsindex
				if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
					if constraintErr := ber.CheckDecodedValue(opts, "ccbs-Index", "(1..5)", fmt.Sprint(int64(*v.CcbsIndex))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode b-subscriberNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_bsubscribernumber, n_bsubscribernumber, rawVal_bsubscribernumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding b-subscriberNumber: %w", err)
				}
				if decodedTag_bsubscribernumber.Class != tag.ClassContextSpecific || decodedTag_bsubscribernumber.Number != 1 {
					return fmt.Errorf("decoding b-subscriberNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bsubscribernumber)
				}
				decVal_bsubscribernumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_bsubscribernumber.Constructed, rawVal_bsubscribernumber, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding b-subscriberNumber: %w", octetErr)
				}
				tmp_bsubscribernumber := ISDNAddressString6(decVal_bsubscribernumber)
				v.BSubscriberNumber = &tmp_bsubscribernumber
				if offset < 0 || offset >
					len(content) || n_bsubscribernumber < 0 || n_bsubscribernumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bsubscribernumber
				if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode b-subscriberSubaddress
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_bsubscribersubaddress, n_bsubscribersubaddress, rawVal_bsubscribersubaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding b-subscriberSubaddress: %w", err)
				}
				if decodedTag_bsubscribersubaddress.Class != tag.ClassContextSpecific || decodedTag_bsubscribersubaddress.Number != 2 {
					return fmt.Errorf("decoding b-subscriberSubaddress: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bsubscribersubaddress)
				}
				decVal_bsubscribersubaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_bsubscribersubaddress.Constructed, rawVal_bsubscribersubaddress, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding b-subscriberSubaddress: %w", octetErr)
				}
				tmp_bsubscribersubaddress := ISDNSubaddressString6(decVal_bsubscribersubaddress)
				v.BSubscriberSubaddress = &tmp_bsubscribersubaddress
				if offset < 0 || offset >
					len(content) || n_bsubscribersubaddress < 0 || n_bsubscribersubaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bsubscribersubaddress
				if len(*v.BSubscriberSubaddress) < 1 || len(*v.BSubscriberSubaddress) > 21 {
					if constraintErr := ber.CheckDecodedLength(opts, "b-subscriberSubaddress", "SIZE (1..21)", len(*v.BSubscriberSubaddress)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode basicServiceGroup
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_basicservicegroup, n_basicservicegroup, innerData_basicservicegroup, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding basicServiceGroup: %w", err)
				}
				if decodedTag_basicservicegroup.Class != tag.ClassContextSpecific || decodedTag_basicservicegroup.Number != 3 || decodedTag_basicservicegroup.Constructed != true {
					return fmt.Errorf("decoding basicServiceGroup: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservicegroup)
				}
				// Decode inner value from explicit tag wrapper
				var dec_basicservicegroup BasicServiceCode6
				if unmErr := dec_basicservicegroup.UnmarshalBER(innerData_basicservicegroup, ber.ChildDecodeOptions(opts, "basicservicegroup")...); unmErr != nil {
					return fmt.Errorf("decoding basicServiceGroup: %w", unmErr)
				}
				v.BasicServiceGroup = &dec_basicservicegroup
				if offset < 0 || offset >
					len(content) || n_basicservicegroup < 0 || n_basicservicegroup >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservicegroup
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CCBSFeature6", Cause: extErr_}
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

// MarshalBER encodes InterrogateSSRes6 to BER format.
func (v *InterrogateSSRes6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InterrogateSSRes6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *InterrogateSSRes6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case InterrogateSSRes6ChoiceSsStatus:
		if v.SsStatus == nil {
			return nil, fmt.Errorf("%w: choice InterrogateSSRes6: ss-Status is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_0)
		}
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_0)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case InterrogateSSRes6ChoiceBasicServiceGroupList:
		enc_1, err := MarshalBERBasicServiceGroupList6(v.BasicServiceGroupList, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList: %w", err)
		}
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(opts, "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList: %w", tagErr_enc_1)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case InterrogateSSRes6ChoiceForwardingFeatureList:
		enc_2, err := MarshalBERForwardingFeatureList6(v.ForwardingFeatureList, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingFeatureList: %w", err)
		}
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(opts, "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, fmt.Errorf("encoding forwardingFeatureList: %w", tagErr_enc_2)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case InterrogateSSRes6ChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("%w: choice InterrogateSSRes6: genericServiceInfo is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.GenericServiceInfo.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo: %w", err)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo: %w", tagErr_enc_3)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for InterrogateSSRes6", v.Choice)
	}
}

// MarshalDER encodes InterrogateSSRes6 to DER format.
func (v *InterrogateSSRes6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InterrogateSSRes6 receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case InterrogateSSRes6ChoiceBasicServiceGroupList:
		enc_der_1, err := MarshalDERBasicServiceGroupList6(v.BasicServiceGroupList)
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList: %w", err)
		}
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(nil, "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList: %w", tagErr_enc_der_1)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList as DER: %w", derErr)
		}
		return enc_der_1, nil
	case InterrogateSSRes6ChoiceForwardingFeatureList:
		enc_der_2, err := MarshalDERForwardingFeatureList6(v.ForwardingFeatureList)
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingFeatureList: %w", err)
		}
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := ber.CheckEncodedLength(nil, "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, fmt.Errorf("encoding forwardingFeatureList: %w", tagErr_enc_der_2)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, fmt.Errorf("encoding forwardingFeatureList as DER: %w", derErr)
		}
		return enc_der_2, nil
	case InterrogateSSRes6ChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("%w: choice InterrogateSSRes6: genericServiceInfo is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.GenericServiceInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo: %w", err)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo: %w", tagErr_enc_der_3)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo as DER: %w", derErr)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding InterrogateSSRes6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes InterrogateSSRes6 from BER/DER format.
func (v *InterrogateSSRes6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: InterrogateSSRes6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
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
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = InterrogateSSRes6{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for InterrogateSSRes6 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InterrogateSSRes6: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("decoding InterrogateSSRes6 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InterrogateSSRes6", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = InterrogateSSRes6ChoiceSsStatus
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding ss-Status: %w", tlvErr)
		}
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return fmt.Errorf("decoding ss-Status: %w", octetErr)
		}
		tmp := SSStatus6(decVal)
		v.SsStatus = &tmp
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = InterrogateSSRes6ChoiceBasicServiceGroupList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding basicServiceGroupList: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERBasicServiceGroupList6(reconstructed, ber.ChildDecodeOptions(opts, "basicServiceGroupList")...)
		if unmErr != nil {
			return fmt.Errorf("decoding basicServiceGroupList: %w", unmErr)
		}
		v.BasicServiceGroupList = dec
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := ber.CheckDecodedLength(opts, "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = InterrogateSSRes6ChoiceForwardingFeatureList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding forwardingFeatureList: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERForwardingFeatureList6(reconstructed, ber.ChildDecodeOptions(opts, "forwardingFeatureList")...)
		if unmErr != nil {
			return fmt.Errorf("decoding forwardingFeatureList: %w", unmErr)
		}
		v.ForwardingFeatureList = dec
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := ber.CheckDecodedLength(opts, "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = InterrogateSSRes6ChoiceGenericServiceInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return fmt.Errorf("decoding genericServiceInfo: %w", tlvErr)
		}
		reconstructed, reconstructionErr := ber.EncodeSequence(rawVal)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec GenericServiceInfo6
		if unmErr := dec.UnmarshalBER(reconstructed, opts...); unmErr != nil {
			return fmt.Errorf("decoding genericServiceInfo: %w", unmErr)
		}
		v.GenericServiceInfo = &dec
	} else {
		return fmt.Errorf("unknown tag %s for InterrogateSSRes6 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes USSDArg6 to BER format.
func (v *USSDArg6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: USSDArg6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *USSDArg6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, fmt.Errorf("encoding ussd-DataCodingScheme: %w", encodeErr_enc_ussddatacodingscheme)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := ber.CheckEncodedLength(opts, "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussdstring, encodeErr_enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	if encodeErr_enc_ussdstring != nil {
		return nil, fmt.Errorf("encoding ussd-String: %w", encodeErr_enc_ussdstring)
	}
	children = append(children, enc_ussdstring...)
	if v.AlertingPattern != nil {
		if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingpattern, encodeErr_enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		if encodeErr_enc_alertingpattern != nil {
			return nil, fmt.Errorf("encoding alertingPattern: %w", encodeErr_enc_alertingpattern)
		}
		children = append(children, enc_alertingpattern...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes USSDArg6 to DER format.
func (v *USSDArg6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: USSDArg6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, fmt.Errorf("encoding ussd-DataCodingScheme: %w", encodeErr_enc_ussddatacodingscheme)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := ber.CheckEncodedLength(nil, "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussdstring, encodeErr_enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	if encodeErr_enc_ussdstring != nil {
		return nil, fmt.Errorf("encoding ussd-String: %w", encodeErr_enc_ussdstring)
	}
	children = append(children, enc_ussdstring...)
	if v.AlertingPattern != nil {
		if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingpattern, encodeErr_enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		if encodeErr_enc_alertingpattern != nil {
			return nil, fmt.Errorf("encoding alertingPattern: %w", encodeErr_enc_alertingpattern)
		}
		children = append(children, enc_alertingpattern...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
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
		return nil, fmt.Errorf("encoding USSDArg6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes USSDArg6 from BER/DER format.
func (v *USSDArg6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: USSDArg6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = USSDArg6{}
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
		return fmt.Errorf("decoding USSDArg6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "USSDArg6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ussd-DataCodingScheme
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-DataCodingScheme")
	}
	val_ussddatacodingscheme, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ussd-DataCodingScheme: %w", err)
	}
	v.UssdDataCodingScheme = USSDDataCodingScheme6(val_ussddatacodingscheme)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	val_ussdstring, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ussd-String: %w", err)
	}
	v.UssdString = USSDString6(val_ussdstring)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := ber.CheckDecodedLength(opts, "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode alertingPattern
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				val_alertingpattern, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding alertingPattern: %w", err)
				}
				tmp_alertingpattern := AlertingPattern6(val_alertingpattern)
				v.AlertingPattern = &tmp_alertingpattern
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
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
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding msisdn: %w", err)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
					return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding msisdn: %w", octetErr)
				}
				tmp_msisdn := ISDNAddressString6(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "USSDArg6", Cause: extErr_}
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

// MarshalBER encodes USSDRes6 to BER format.
func (v *USSDRes6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: USSDRes6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *USSDRes6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, fmt.Errorf("encoding ussd-DataCodingScheme: %w", encodeErr_enc_ussddatacodingscheme)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := ber.CheckEncodedLength(opts, "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussdstring, encodeErr_enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	if encodeErr_enc_ussdstring != nil {
		return nil, fmt.Errorf("encoding ussd-String: %w", encodeErr_enc_ussdstring)
	}
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes USSDRes6 to DER format.
func (v *USSDRes6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: USSDRes6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, fmt.Errorf("encoding ussd-DataCodingScheme: %w", encodeErr_enc_ussddatacodingscheme)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := ber.CheckEncodedLength(nil, "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussdstring, encodeErr_enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	if encodeErr_enc_ussdstring != nil {
		return nil, fmt.Errorf("encoding ussd-String: %w", encodeErr_enc_ussdstring)
	}
	children = append(children, enc_ussdstring...)
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
		return nil, fmt.Errorf("encoding USSDRes6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes USSDRes6 from BER/DER format.
func (v *USSDRes6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: USSDRes6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = USSDRes6{}
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
		return fmt.Errorf("decoding USSDRes6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "USSDRes6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ussd-DataCodingScheme
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-DataCodingScheme")
	}
	val_ussddatacodingscheme, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ussd-DataCodingScheme: %w", err)
	}
	v.UssdDataCodingScheme = USSDDataCodingScheme6(val_ussddatacodingscheme)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	val_ussdstring, n, err := ber.DecodeOctetString(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ussd-String: %w", err)
	}
	v.UssdString = USSDString6(val_ussdstring)
	if offset < 0 || offset >
		len(content) || n < 0 || n > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := ber.CheckDecodedLength(opts, "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return constraintErr
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "USSDRes6", Cause: extErr_}
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

// MarshalBERSSList6 encodes a SSList6 list to BER.
func MarshalBERSSList6(collection *SSList6, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERSSList6(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERSSList6(collection *SSList6, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := ber.CheckEncodedLength(opts, "SSList6", "SIZE (1..30)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERSSList6 encodes a SSList6 list to DER.
func MarshalDERSSList6(collection *SSList6) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := ber.CheckEncodedLength(nil, "SSList6", "SIZE (1..30)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSList6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERSSList6 decodes a SSList6 list from BER.
func UnmarshalBERSSList6(data []byte, opts ...ber.DecodeOption) (*SSList6, error) {
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding SSList6: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSList6", Cause: ber.ErrExtraData}
	}
	var result []SSCode6
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:], opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 1 || len(val) > 1 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, SSCode6(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 30 {
		if constraintErr := ber.CheckDecodedLength(opts, "SSList6", "SIZE (1..30)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSList6{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERSSList6(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERSSInfoList6 encodes a SSInfoList6 list to BER.
func MarshalBERSSInfoList6(collection *SSInfoList6, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERSSInfoList6(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERSSInfoList6(collection *SSInfoList6, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := ber.CheckEncodedLength(opts, "SSInfoList6", "SIZE (1..30)", len(list)); constraintErr != nil {
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

// MarshalDERSSInfoList6 encodes a SSInfoList6 list to DER.
func MarshalDERSSInfoList6(collection *SSInfoList6) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := ber.CheckEncodedLength(nil, "SSInfoList6", "SIZE (1..30)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("encoding SSInfoList6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERSSInfoList6 decodes a SSInfoList6 list from BER.
func UnmarshalBERSSInfoList6(data []byte, opts ...ber.DecodeOption) (*SSInfoList6, error) {
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding SSInfoList6: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSInfoList6", Cause: ber.ErrExtraData}
	}
	var result []SSInfo6
	offset := 0
	for offset < len(content) {
		var elem SSInfo6
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
	if len(result) < 1 || len(result) > 30 {
		if constraintErr := ber.CheckDecodedLength(opts, "SSInfoList6", "SIZE (1..30)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSInfoList6{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERSSInfoList6(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBERBasicServiceGroupList6 encodes a BasicServiceGroupList6 list to BER.
func MarshalBERBasicServiceGroupList6(collection *BasicServiceGroupList6, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERBasicServiceGroupList6(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERBasicServiceGroupList6(collection *BasicServiceGroupList6, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedLength(opts, "BasicServiceGroupList6", "SIZE (1..13)", len(list)); constraintErr != nil {
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

// MarshalDERBasicServiceGroupList6 encodes a BasicServiceGroupList6 list to DER.
func MarshalDERBasicServiceGroupList6(collection *BasicServiceGroupList6) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := ber.CheckEncodedLength(nil, "BasicServiceGroupList6", "SIZE (1..13)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("encoding BasicServiceGroupList6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERBasicServiceGroupList6 decodes a BasicServiceGroupList6 list from BER.
func UnmarshalBERBasicServiceGroupList6(data []byte, opts ...ber.DecodeOption) (*BasicServiceGroupList6, error) {
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding BasicServiceGroupList6: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BasicServiceGroupList6", Cause: ber.ErrExtraData}
	}
	var result []BasicServiceCode6
	offset := 0
	for offset < len(content) {
		var elem BasicServiceCode6
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
	if len(result) < 1 || len(result) > 13 {
		if constraintErr := ber.CheckDecodedLength(opts, "BasicServiceGroupList6", "SIZE (1..13)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &BasicServiceGroupList6{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERBasicServiceGroupList6(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes SSInvocationNotificationArg6 to BER format.
func (v *SSInvocationNotificationArg6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSInvocationNotificationArg6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSInvocationNotificationArg6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if len(v.SsEvent) < 1 || len(v.SsEvent) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Event", "SIZE (1)", len(v.SsEvent)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssevent, encodeErr_enc_ssevent := ber.EncodeOctetString([]byte(v.SsEvent))
	if encodeErr_enc_ssevent != nil {
		return nil, fmt.Errorf("encoding ss-Event: %w", encodeErr_enc_ssevent)
	}
	retagged_enc_ssevent, tagErr_enc_ssevent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ssevent)
	if tagErr_enc_ssevent != nil {
		return nil, fmt.Errorf("encoding ss-Event: %w", tagErr_enc_ssevent)
	}
	enc_ssevent = retagged_enc_ssevent
	children = append(children, enc_ssevent...)
	if v.SsEventSpecification != nil {
		if len((v.SsEventSpecification).Values) < 1 || len((v.SsEventSpecification).Values) > 2 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-EventSpecification", "SIZE (1..2)", len((v.SsEventSpecification).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sseventspecification, err := MarshalBERSSEventSpecification6(v.SsEventSpecification, opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding ss-EventSpecification: %w", err)
		}
		if v.SsEventSpecificationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeTLV(enc_sseventspecification)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_sseventspecification, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
				if encodeErr != nil {
					return nil, fmt.Errorf("encoding ss-EventSpecification: %w", encodeErr)
				}
			}
		} else {
			retagged_enc_sseventspecification, tagErr_enc_sseventspecification := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_sseventspecification)
			if tagErr_enc_sseventspecification != nil {
				return nil, fmt.Errorf("encoding ss-EventSpecification: %w", tagErr_enc_sseventspecification)
			}
			enc_sseventspecification = retagged_enc_sseventspecification
		}
		children = append(children, enc_sseventspecification...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(opts...)
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
	if v.BSubscriberNumber != nil {
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(opts, "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribernumber, encodeErr_enc_bsubscribernumber := ber.EncodeOctetString([]byte(*v.BSubscriberNumber))
		if encodeErr_enc_bsubscribernumber != nil {
			return nil, fmt.Errorf("encoding b-subscriberNumber: %w", encodeErr_enc_bsubscribernumber)
		}
		retagged_enc_bsubscribernumber, tagErr_enc_bsubscribernumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bsubscribernumber)
		if tagErr_enc_bsubscribernumber != nil {
			return nil, fmt.Errorf("encoding b-subscriberNumber: %w", tagErr_enc_bsubscribernumber)
		}
		enc_bsubscribernumber = retagged_enc_bsubscribernumber
		children = append(children, enc_bsubscribernumber...)
	}
	if v.CcbsRequestState != nil {
		if int64(*v.CcbsRequestState) != 0 && int64(*v.CcbsRequestState) != 1 && int64(*v.CcbsRequestState) != 2 && int64(*v.CcbsRequestState) != 3 && int64(*v.CcbsRequestState) != 4 && int64(*v.CcbsRequestState) != 5 && int64(*v.CcbsRequestState) != 6 {
			if constraintErr := ber.CheckEncodedValue(opts, "ccbs-RequestState", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(*v.CcbsRequestState))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsrequeststate := ber.EncodeEnumerated(int64(*v.CcbsRequestState))
		retagged_enc_ccbsrequeststate, tagErr_enc_ccbsrequeststate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ccbsrequeststate)
		if tagErr_enc_ccbsrequeststate != nil {
			return nil, fmt.Errorf("encoding ccbs-RequestState: %w", tagErr_enc_ccbsrequeststate)
		}
		enc_ccbsrequeststate = retagged_enc_ccbsrequeststate
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes SSInvocationNotificationArg6 to DER format.
func (v *SSInvocationNotificationArg6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSInvocationNotificationArg6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckEncodedLength(nil, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", encodeErr_enc_imsi)
	}
	retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
	if tagErr_enc_imsi != nil {
		return nil, fmt.Errorf("encoding imsi: %w", tagErr_enc_imsi)
	}
	enc_imsi = retagged_enc_imsi
	children = append(children, enc_imsi...)
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", encodeErr_enc_msisdn)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, fmt.Errorf("encoding msisdn: %w", tagErr_enc_msisdn)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if len(v.SsEvent) < 1 || len(v.SsEvent) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Event", "SIZE (1)", len(v.SsEvent)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssevent, encodeErr_enc_ssevent := ber.EncodeOctetString([]byte(v.SsEvent))
	if encodeErr_enc_ssevent != nil {
		return nil, fmt.Errorf("encoding ss-Event: %w", encodeErr_enc_ssevent)
	}
	retagged_enc_ssevent, tagErr_enc_ssevent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ssevent)
	if tagErr_enc_ssevent != nil {
		return nil, fmt.Errorf("encoding ss-Event: %w", tagErr_enc_ssevent)
	}
	enc_ssevent = retagged_enc_ssevent
	children = append(children, enc_ssevent...)
	if v.SsEventSpecification != nil {
		if len((v.SsEventSpecification).Values) < 1 || len((v.SsEventSpecification).Values) > 2 {
			if constraintErr := ber.CheckEncodedLength(nil, "ss-EventSpecification", "SIZE (1..2)", len((v.SsEventSpecification).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sseventspecification, err := MarshalDERSSEventSpecification6(v.SsEventSpecification)
		if err != nil {
			return nil, fmt.Errorf("encoding ss-EventSpecification: %w", err)
		}
		retagged_enc_sseventspecification, tagErr_enc_sseventspecification := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_sseventspecification)
		if tagErr_enc_sseventspecification != nil {
			return nil, fmt.Errorf("encoding ss-EventSpecification: %w", tagErr_enc_sseventspecification)
		}
		enc_sseventspecification = retagged_enc_sseventspecification
		children = append(children, enc_sseventspecification...)
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
	if v.BSubscriberNumber != nil {
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
			if constraintErr := ber.CheckEncodedLength(nil, "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribernumber, encodeErr_enc_bsubscribernumber := ber.EncodeOctetString([]byte(*v.BSubscriberNumber))
		if encodeErr_enc_bsubscribernumber != nil {
			return nil, fmt.Errorf("encoding b-subscriberNumber: %w", encodeErr_enc_bsubscribernumber)
		}
		retagged_enc_bsubscribernumber, tagErr_enc_bsubscribernumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bsubscribernumber)
		if tagErr_enc_bsubscribernumber != nil {
			return nil, fmt.Errorf("encoding b-subscriberNumber: %w", tagErr_enc_bsubscribernumber)
		}
		enc_bsubscribernumber = retagged_enc_bsubscribernumber
		children = append(children, enc_bsubscribernumber...)
	}
	if v.CcbsRequestState != nil {
		if int64(*v.CcbsRequestState) != 0 && int64(*v.CcbsRequestState) != 1 && int64(*v.CcbsRequestState) != 2 && int64(*v.CcbsRequestState) != 3 && int64(*v.CcbsRequestState) != 4 && int64(*v.CcbsRequestState) != 5 && int64(*v.CcbsRequestState) != 6 {
			if constraintErr := ber.CheckEncodedValue(nil, "ccbs-RequestState", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(*v.CcbsRequestState))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsrequeststate := ber.EncodeEnumerated(int64(*v.CcbsRequestState))
		retagged_enc_ccbsrequeststate, tagErr_enc_ccbsrequeststate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ccbsrequeststate)
		if tagErr_enc_ccbsrequeststate != nil {
			return nil, fmt.Errorf("encoding ccbs-RequestState: %w", tagErr_enc_ccbsrequeststate)
		}
		enc_ccbsrequeststate = retagged_enc_ccbsrequeststate
		children = append(children, enc_ccbsrequeststate...)
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
		return nil, fmt.Errorf("encoding SSInvocationNotificationArg6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSInvocationNotificationArg6 from BER/DER format.
func (v *SSInvocationNotificationArg6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSInvocationNotificationArg6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSInvocationNotificationArg6{}
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
		return fmt.Errorf("decoding SSInvocationNotificationArg6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInvocationNotificationArg6", Cause: ber.ErrExtraData}
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
	decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding imsi: %w", err)
	}
	if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
		return fmt.Errorf("decoding imsi: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi)
	}
	decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding imsi: %w", octetErr)
	}
	v.Imsi = IMSI6(decVal_imsi)
	if offset < 0 || offset >
		len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_imsi
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := ber.CheckDecodedLength(opts, "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode msisdn
	if offset >= len(content) {
		return fmt.Errorf("missing required field msisdn")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for msisdn, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding msisdn: %w", err)
	}
	if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 1 {
		return fmt.Errorf("decoding msisdn: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn)
	}
	decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding msisdn: %w", octetErr)
	}
	v.Msisdn = ISDNAddressString6(decVal_msisdn)
	if offset < 0 || offset >
		len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_msisdn
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode ss-Event
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Event")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("expected tag [%s %d] for ss-Event, got %s", "CONTEXT", 2, reqTag_)
		}
	}
	decodedTag_ssevent, n_ssevent, rawVal_ssevent, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ss-Event: %w", err)
	}
	if decodedTag_ssevent.Class != tag.ClassContextSpecific || decodedTag_ssevent.Number != 2 {
		return fmt.Errorf("decoding ss-Event: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssevent)
	}
	decVal_ssevent, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssevent.Constructed, rawVal_ssevent, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding ss-Event: %w", octetErr)
	}
	v.SsEvent = SSCode6(decVal_ssevent)
	if offset < 0 || offset >
		len(content) || n_ssevent < 0 || n_ssevent > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_ssevent
	if len(v.SsEvent) < 1 || len(v.SsEvent) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ss-Event", "SIZE (1)", len(v.SsEvent)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode ss-EventSpecification
	v.SsEventSpecificationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				decodedTag_sseventspecification, n_sseventspecification, rawVal_sseventspecification, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ss-EventSpecification: %w", err)
				}
				if decodedTag_sseventspecification.Class != tag.ClassContextSpecific || decodedTag_sseventspecification.Number != 3 || decodedTag_sseventspecification.Constructed != true {
					return fmt.Errorf("decoding ss-EventSpecification: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sseventspecification)
				}
				reconstructed_sseventspecification, reconstructionErr_sseventspecification := ber.EncodeSequence(rawVal_sseventspecification)
				if reconstructionErr_sseventspecification != nil {
					return fmt.Errorf("decoding ss-EventSpecification: %w", reconstructionErr_sseventspecification)
				}
				dec_sseventspecification, unmErr := UnmarshalBERSSEventSpecification6(reconstructed_sseventspecification, ber.ChildDecodeOptions(opts, "ss-EventSpecification")...)
				if unmErr != nil {
					return fmt.Errorf("decoding ss-EventSpecification: %w", unmErr)
				}
				v.SsEventSpecification = dec_sseventspecification
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.SsEventSpecificationIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_sseventspecification < 0 || n_sseventspecification >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sseventspecification
				if len((v.SsEventSpecification).Values) < 1 || len((v.SsEventSpecification).Values) > 2 {
					if constraintErr := ber.CheckDecodedLength(opts, "ss-EventSpecification", "SIZE (1..2)", len((v.SsEventSpecification).Values)); constraintErr != nil {
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
				var dec_extensioncontainer ExtensionContainer6
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
	// Decode b-subscriberNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				decodedTag_bsubscribernumber, n_bsubscribernumber, rawVal_bsubscribernumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding b-subscriberNumber: %w", err)
				}
				if decodedTag_bsubscribernumber.Class != tag.ClassContextSpecific || decodedTag_bsubscribernumber.Number != 5 {
					return fmt.Errorf("decoding b-subscriberNumber: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bsubscribernumber)
				}
				decVal_bsubscribernumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_bsubscribernumber.Constructed, rawVal_bsubscribernumber, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding b-subscriberNumber: %w", octetErr)
				}
				tmp_bsubscribernumber := ISDNAddressString6(decVal_bsubscribernumber)
				v.BSubscriberNumber = &tmp_bsubscribernumber
				if offset < 0 || offset >
					len(content) || n_bsubscribernumber < 0 || n_bsubscribernumber > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bsubscribernumber
				if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
					if constraintErr := ber.CheckDecodedLength(opts, "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
					if constraintErr := ber.CheckDecodedLength(opts, "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ccbs-RequestState
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				decodedTag_ccbsrequeststate, n_ccbsrequeststate, rawVal_ccbsrequeststate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ccbs-RequestState: %w", err)
				}
				if decodedTag_ccbsrequeststate.Class != tag.ClassContextSpecific || decodedTag_ccbsrequeststate.Number != 6 || decodedTag_ccbsrequeststate.Constructed != false {
					return fmt.Errorf("decoding ccbs-RequestState: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsrequeststate)
				}
				decVal_ccbsrequeststate, intErr := ber.DecodeEnumeratedValue(rawVal_ccbsrequeststate)
				if intErr != nil {
					return fmt.Errorf("decoding ccbs-RequestState: %w", intErr)
				}
				tmp_ccbsrequeststate := CCBSRequestState6(decVal_ccbsrequeststate)
				v.CcbsRequestState = &tmp_ccbsrequeststate
				if offset < 0 || offset >
					len(content) || n_ccbsrequeststate < 0 || n_ccbsrequeststate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsrequeststate
				if int64(*v.CcbsRequestState) != 0 && int64(*v.CcbsRequestState) != 1 && int64(*v.CcbsRequestState) != 2 && int64(*v.CcbsRequestState) != 3 && int64(*v.CcbsRequestState) != 4 && int64(*v.CcbsRequestState) != 5 && int64(*v.CcbsRequestState) != 6 {
					if constraintErr := ber.CheckDecodedValue(opts, "ccbs-RequestState", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", fmt.Sprint(int64(*v.CcbsRequestState))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSInvocationNotificationArg6", Cause: extErr_}
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

// MarshalBER encodes SSInvocationNotificationRes6 to BER format.
func (v *SSInvocationNotificationRes6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSInvocationNotificationRes6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *SSInvocationNotificationRes6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
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

// MarshalDER encodes SSInvocationNotificationRes6 to DER format.
func (v *SSInvocationNotificationRes6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSInvocationNotificationRes6 receiver is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("encoding SSInvocationNotificationRes6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSInvocationNotificationRes6 from BER/DER format.
func (v *SSInvocationNotificationRes6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: SSInvocationNotificationRes6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = SSInvocationNotificationRes6{}
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
		return fmt.Errorf("decoding SSInvocationNotificationRes6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInvocationNotificationRes6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer6)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer6
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensioncontainer")...); unmErr != nil {
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
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSInvocationNotificationRes6", Cause: extErr_}
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

// MarshalBERSSEventSpecification6 encodes a SSEventSpecification6 list to BER.
func MarshalBERSSEventSpecification6(collection *SSEventSpecification6, opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	encoded, err := marshalBERSSEventSpecification6(collection, opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, collection.berOriginal_, collection.berSnapshot_, opts), nil
}
func marshalBERSSEventSpecification6(collection *SSEventSpecification6, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 2 {
		if constraintErr := ber.CheckEncodedLength(opts, "SSEventSpecification6", "SIZE (1..2)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := ber.CheckEncodedLength(opts, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	return ber.EncodeSequence(children)
}

// MarshalDERSSEventSpecification6 encodes a SSEventSpecification6 list to DER.
func MarshalDERSSEventSpecification6(collection *SSEventSpecification6) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 2 {
		if constraintErr := ber.CheckEncodedLength(nil, "SSEventSpecification6", "SIZE (1..2)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := ber.CheckEncodedLength(nil, fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		encodedElem, encodeErr_encodedElem := ber.EncodeOctetString([]byte(elem))
		if encodeErr_encodedElem != nil {
			return nil, fmt.Errorf("encoding element: %w", encodeErr_encodedElem)
		}
		children = append(children, encodedElem...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSEventSpecification6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBERSSEventSpecification6 decodes a SSEventSpecification6 list from BER.
func UnmarshalBERSSEventSpecification6(data []byte, opts ...ber.DecodeOption) (*SSEventSpecification6, error) {
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return nil, err
	}
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("decoding SSEventSpecification6: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSEventSpecification6", Cause: ber.ErrExtraData}
	}
	var result []AddressString6
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:], opts...)
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		if len(val) < 1 || len(val) > 20 {
			if constraintErr := ber.CheckDecodedLength(opts, fmt.Sprintf("element[%d]", len(result)), "SIZE (1..20)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, AddressString6(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 2 {
		if constraintErr := ber.CheckDecodedLength(opts, "SSEventSpecification6", "SIZE (1..2)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSEventSpecification6{Values: result}
	if ber.BERNeedsPreservation(opts) {
		var snapshotReports ber.ViolationLog
		snapshot, snapshotErr := MarshalBERSSEventSpecification6(decoded, ber.WithConstraintTolerance(&snapshotReports))
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		decoded.berOriginal_ = append([]byte(nil), data...)
		decoded.berSnapshot_ = snapshot
	}
	return decoded, nil
}

// MarshalBER encodes RegisterCCEntryArg6 to BER format.
func (v *RegisterCCEntryArg6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RegisterCCEntryArg6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RegisterCCEntryArg6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.CcbsData != nil {
		enc_ccbsdata, err := v.CcbsData.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-Data: %w", err)
		}
		retagged_enc_ccbsdata, tagErr_enc_ccbsdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ccbsdata)
		if tagErr_enc_ccbsdata != nil {
			return nil, fmt.Errorf("encoding ccbs-Data: %w", tagErr_enc_ccbsdata)
		}
		enc_ccbsdata = retagged_enc_ccbsdata
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes RegisterCCEntryArg6 to DER format.
func (v *RegisterCCEntryArg6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RegisterCCEntryArg6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.CcbsData != nil {
		enc_ccbsdata, err := v.CcbsData.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-Data: %w", err)
		}
		retagged_enc_ccbsdata, tagErr_enc_ccbsdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ccbsdata)
		if tagErr_enc_ccbsdata != nil {
			return nil, fmt.Errorf("encoding ccbs-Data: %w", tagErr_enc_ccbsdata)
		}
		enc_ccbsdata = retagged_enc_ccbsdata
		children = append(children, enc_ccbsdata...)
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
		return nil, fmt.Errorf("encoding RegisterCCEntryArg6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RegisterCCEntryArg6 from BER/DER format.
func (v *RegisterCCEntryArg6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RegisterCCEntryArg6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RegisterCCEntryArg6{}
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
		return fmt.Errorf("decoding RegisterCCEntryArg6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterCCEntryArg6", Cause: ber.ErrExtraData}
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
	decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
		return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
	}
	decVal_sscode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sscode.Constructed, rawVal_sscode, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding ss-Code: %w", octetErr)
	}
	v.SsCode = SSCode6(decVal_sscode)
	if offset < 0 || offset >
		len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_sscode
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode ccbs-Data
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_ccbsdata, n_ccbsdata, rawVal_ccbsdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ccbs-Data: %w", err)
				}
				if decodedTag_ccbsdata.Class != tag.ClassContextSpecific || decodedTag_ccbsdata.Number != 1 || decodedTag_ccbsdata.Constructed != true {
					return fmt.Errorf("decoding ccbs-Data: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsdata)
				}
				reconstructed_ccbsdata, reconstructionErr_ccbsdata := ber.EncodeSequence(rawVal_ccbsdata)
				if reconstructionErr_ccbsdata != nil {
					return fmt.Errorf("decoding ccbs-Data: %w", reconstructionErr_ccbsdata)
				}
				var dec_ccbsdata CCBSData6
				if unmErr := dec_ccbsdata.UnmarshalBER(reconstructed_ccbsdata, ber.ChildDecodeOptions(opts, "ccbsdata")...); unmErr != nil {
					return fmt.Errorf("decoding ccbs-Data: %w", unmErr)
				}
				v.CcbsData = &dec_ccbsdata
				if offset < 0 || offset >
					len(content) || n_ccbsdata < 0 || n_ccbsdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsdata
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterCCEntryArg6", Cause: extErr_}
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

// MarshalBER encodes CCBSData6 to BER format.
func (v *CCBSData6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CCBSData6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *CCBSData6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_ccbsfeature, err := v.CcbsFeature.MarshalBER(opts...)
	if err != nil {
		return nil, fmt.Errorf("encoding ccbs-Feature: %w", err)
	}
	retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsfeature)
	if tagErr_enc_ccbsfeature != nil {
		return nil, fmt.Errorf("encoding ccbs-Feature: %w", tagErr_enc_ccbsfeature)
	}
	enc_ccbsfeature = retagged_enc_ccbsfeature
	children = append(children, enc_ccbsfeature...)
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(opts, "translatedB-Number", "SIZE (1..9)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(opts, "translatedB-Number", "SIZE (1..20)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_translatedbnumber, encodeErr_enc_translatedbnumber := ber.EncodeOctetString([]byte(v.TranslatedBNumber))
	if encodeErr_enc_translatedbnumber != nil {
		return nil, fmt.Errorf("encoding translatedB-Number: %w", encodeErr_enc_translatedbnumber)
	}
	retagged_enc_translatedbnumber, tagErr_enc_translatedbnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_translatedbnumber)
	if tagErr_enc_translatedbnumber != nil {
		return nil, fmt.Errorf("encoding translatedB-Number: %w", tagErr_enc_translatedbnumber)
	}
	enc_translatedbnumber = retagged_enc_translatedbnumber
	children = append(children, enc_translatedbnumber...)
	if v.ServiceIndicator != nil {
		if (*v.ServiceIndicator).BitLength < 2 || (*v.ServiceIndicator).BitLength > 32 {
			if constraintErr := ber.CheckEncodedLength(opts, "serviceIndicator", "SIZE (2..32)", (*v.ServiceIndicator).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.ServiceIndicator.Bytes, v.ServiceIndicator.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "serviceIndicator", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:523
		if v.ServiceIndicator.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_serviceindicator, encodeErr_enc_serviceindicator := ber.EncodeBitString(v.ServiceIndicator.Bytes, (8-(v.ServiceIndicator.BitLength%8))%8)
		if encodeErr_enc_serviceindicator != nil {
			return nil, fmt.Errorf("encoding serviceIndicator: %w", encodeErr_enc_serviceindicator)
		}
		retagged_enc_serviceindicator, tagErr_enc_serviceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_serviceindicator)
		if tagErr_enc_serviceindicator != nil {
			return nil, fmt.Errorf("encoding serviceIndicator: %w", tagErr_enc_serviceindicator)
		}
		enc_serviceindicator = retagged_enc_serviceindicator
		children = append(children, enc_serviceindicator...)
	}
	enc_callinfo, err := v.CallInfo.MarshalBER(opts...)
	if err != nil {
		return nil, fmt.Errorf("encoding callInfo: %w", err)
	}
	retagged_enc_callinfo, tagErr_enc_callinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_callinfo)
	if tagErr_enc_callinfo != nil {
		return nil, fmt.Errorf("encoding callInfo: %w", tagErr_enc_callinfo)
	}
	enc_callinfo = retagged_enc_callinfo
	children = append(children, enc_callinfo...)
	enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER(opts...)
	if err != nil {
		return nil, fmt.Errorf("encoding networkSignalInfo: %w", err)
	}
	retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_networksignalinfo)
	if tagErr_enc_networksignalinfo != nil {
		return nil, fmt.Errorf("encoding networkSignalInfo: %w", tagErr_enc_networksignalinfo)
	}
	enc_networksignalinfo = retagged_enc_networksignalinfo
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes CCBSData6 to DER format.
func (v *CCBSData6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CCBSData6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_ccbsfeature, err := v.CcbsFeature.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding ccbs-Feature: %w", err)
	}
	retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsfeature)
	if tagErr_enc_ccbsfeature != nil {
		return nil, fmt.Errorf("encoding ccbs-Feature: %w", tagErr_enc_ccbsfeature)
	}
	enc_ccbsfeature = retagged_enc_ccbsfeature
	children = append(children, enc_ccbsfeature...)
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 9 {
		if constraintErr := ber.CheckEncodedLength(nil, "translatedB-Number", "SIZE (1..9)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 20 {
		if constraintErr := ber.CheckEncodedLength(nil, "translatedB-Number", "SIZE (1..20)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_translatedbnumber, encodeErr_enc_translatedbnumber := ber.EncodeOctetString([]byte(v.TranslatedBNumber))
	if encodeErr_enc_translatedbnumber != nil {
		return nil, fmt.Errorf("encoding translatedB-Number: %w", encodeErr_enc_translatedbnumber)
	}
	retagged_enc_translatedbnumber, tagErr_enc_translatedbnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_translatedbnumber)
	if tagErr_enc_translatedbnumber != nil {
		return nil, fmt.Errorf("encoding translatedB-Number: %w", tagErr_enc_translatedbnumber)
	}
	enc_translatedbnumber = retagged_enc_translatedbnumber
	children = append(children, enc_translatedbnumber...)
	if v.ServiceIndicator != nil {
		if (*v.ServiceIndicator).BitLength < 2 || (*v.ServiceIndicator).BitLength > 32 {
			if constraintErr := ber.CheckEncodedLength(nil, "serviceIndicator", "SIZE (2..32)", (*v.ServiceIndicator).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if bitStringErr := ber.ValidateBitStringLength(v.ServiceIndicator.Bytes, v.ServiceIndicator.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "serviceIndicator", bitStringErr)
		}
		if bitStringErr := ber.ValidateDERBitString(v.ServiceIndicator.Bytes, v.ServiceIndicator.BitLength); bitStringErr != nil {
			return nil, fmt.Errorf("encoding %s: %w", "serviceIndicator", bitStringErr)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:523
		if v.ServiceIndicator.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		enc_serviceindicator, encodeErr_enc_serviceindicator := ber.EncodeBitString(v.ServiceIndicator.Bytes, (8-(v.ServiceIndicator.BitLength%8))%8)
		if encodeErr_enc_serviceindicator != nil {
			return nil, fmt.Errorf("encoding serviceIndicator: %w", encodeErr_enc_serviceindicator)
		}
		retagged_enc_serviceindicator, tagErr_enc_serviceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_serviceindicator)
		if tagErr_enc_serviceindicator != nil {
			return nil, fmt.Errorf("encoding serviceIndicator: %w", tagErr_enc_serviceindicator)
		}
		enc_serviceindicator = retagged_enc_serviceindicator
		children = append(children, enc_serviceindicator...)
	}
	enc_callinfo, err := v.CallInfo.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding callInfo: %w", err)
	}
	retagged_enc_callinfo, tagErr_enc_callinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_callinfo)
	if tagErr_enc_callinfo != nil {
		return nil, fmt.Errorf("encoding callInfo: %w", tagErr_enc_callinfo)
	}
	enc_callinfo = retagged_enc_callinfo
	children = append(children, enc_callinfo...)
	enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalDER()
	if err != nil {
		return nil, fmt.Errorf("encoding networkSignalInfo: %w", err)
	}
	retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_networksignalinfo)
	if tagErr_enc_networksignalinfo != nil {
		return nil, fmt.Errorf("encoding networkSignalInfo: %w", tagErr_enc_networksignalinfo)
	}
	enc_networksignalinfo = retagged_enc_networksignalinfo
	children = append(children, enc_networksignalinfo...)
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
		return nil, fmt.Errorf("encoding CCBSData6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CCBSData6 from BER/DER format.
func (v *CCBSData6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: CCBSData6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = CCBSData6{}
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
		return fmt.Errorf("decoding CCBSData6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CCBSData6", Cause: ber.ErrExtraData}
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
	decodedTag_ccbsfeature, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ccbs-Feature: %w", err)
	}
	if decodedTag_ccbsfeature.Class != tag.ClassContextSpecific || decodedTag_ccbsfeature.Number != 0 || decodedTag_ccbsfeature.Constructed != true {
		return fmt.Errorf("decoding ccbs-Feature: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsfeature)
	}
	reconstructed_ccbsfeature, reconstructionErr_ccbsfeature := ber.EncodeSequence(rawVal_ccbsfeature)
	if reconstructionErr_ccbsfeature != nil {
		return fmt.Errorf("decoding ccbs-Feature: %w", reconstructionErr_ccbsfeature)
	}
	if unmErr := v.CcbsFeature.UnmarshalBER(reconstructed_ccbsfeature, ber.ChildDecodeOptions(opts, "ccbsFeature")...); unmErr != nil {
		return fmt.Errorf("decoding ccbs-Feature: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_ccbsfeature < 0 || n_ccbsfeature >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
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
	decodedTag_translatedbnumber, n_translatedbnumber, rawVal_translatedbnumber, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding translatedB-Number: %w", err)
	}
	if decodedTag_translatedbnumber.Class != tag.ClassContextSpecific || decodedTag_translatedbnumber.Number != 1 {
		return fmt.Errorf("decoding translatedB-Number: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_translatedbnumber)
	}
	decVal_translatedbnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_translatedbnumber.Constructed, rawVal_translatedbnumber, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding translatedB-Number: %w", octetErr)
	}
	v.TranslatedBNumber = ISDNAddressString6(decVal_translatedbnumber)
	if offset < 0 || offset >
		len(content) || n_translatedbnumber < 0 || n_translatedbnumber >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_translatedbnumber
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 9 {
		if constraintErr := ber.CheckDecodedLength(opts, "translatedB-Number", "SIZE (1..9)", len(v.TranslatedBNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 20 {
		if constraintErr := ber.CheckDecodedLength(opts, "translatedB-Number", "SIZE (1..20)", len(v.TranslatedBNumber)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode serviceIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				decodedTag_serviceindicator, n_serviceindicator, rawVal_serviceindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding serviceIndicator: %w", err)
				}
				if decodedTag_serviceindicator.Class != tag.ClassContextSpecific || decodedTag_serviceindicator.Number != 2 {
					return fmt.Errorf("decoding serviceIndicator: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_serviceindicator)
				}
				bsBytes_serviceindicator, bsUnused_serviceindicator, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_serviceindicator.Constructed, rawVal_serviceindicator, opts...)
				if bsErr != nil {
					return fmt.Errorf("decoding serviceIndicator: %w", bsErr)
				}
				bsBitLength_serviceindicator, bsLenErr_serviceindicator := ber.BitStringBitLength(len(bsBytes_serviceindicator), bsUnused_serviceindicator)
				if bsLenErr_serviceindicator != nil {
					return fmt.Errorf("decoding serviceIndicator: %w", bsLenErr_serviceindicator)
				}
				tmp_serviceindicator := runtime.BitString{Bytes: bsBytes_serviceindicator, BitLength: bsBitLength_serviceindicator}
				v.ServiceIndicator = &tmp_serviceindicator
				if offset < 0 || offset >
					len(content) || n_serviceindicator < 0 || n_serviceindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_serviceindicator
				if (*v.ServiceIndicator).BitLength < 2 || (*v.ServiceIndicator).BitLength > 32 {
					if constraintErr := ber.CheckDecodedLength(opts, "serviceIndicator", "SIZE (2..32)", (*v.ServiceIndicator).BitLength); constraintErr != nil {
						return constraintErr
					}
				}
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
	decodedTag_callinfo, n_callinfo, rawVal_callinfo, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding callInfo: %w", err)
	}
	if decodedTag_callinfo.Class != tag.ClassContextSpecific || decodedTag_callinfo.Number != 3 || decodedTag_callinfo.Constructed != true {
		return fmt.Errorf("decoding callInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callinfo)
	}
	reconstructed_callinfo, reconstructionErr_callinfo := ber.EncodeSequence(rawVal_callinfo)
	if reconstructionErr_callinfo != nil {
		return fmt.Errorf("decoding callInfo: %w", reconstructionErr_callinfo)
	}
	if unmErr := v.CallInfo.UnmarshalBER(reconstructed_callinfo, ber.ChildDecodeOptions(opts, "callInfo")...); unmErr != nil {
		return fmt.Errorf("decoding callInfo: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_callinfo < 0 || n_callinfo > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
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
	decodedTag_networksignalinfo, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding networkSignalInfo: %w", err)
	}
	if decodedTag_networksignalinfo.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo.Number != 4 || decodedTag_networksignalinfo.Constructed != true {
		return fmt.Errorf("decoding networkSignalInfo: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo)
	}
	reconstructed_networksignalinfo, reconstructionErr_networksignalinfo := ber.EncodeSequence(rawVal_networksignalinfo)
	if reconstructionErr_networksignalinfo != nil {
		return fmt.Errorf("decoding networkSignalInfo: %w", reconstructionErr_networksignalinfo)
	}
	if unmErr := v.NetworkSignalInfo.UnmarshalBER(reconstructed_networksignalinfo, ber.ChildDecodeOptions(opts, "networkSignalInfo")...); unmErr != nil {
		return fmt.Errorf("decoding networkSignalInfo: %w", unmErr)
	}
	if offset < 0 || offset >
		len(content) || n_networksignalinfo < 0 || n_networksignalinfo >
		len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_networksignalinfo
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "CCBSData6", Cause: extErr_}
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

// MarshalBER encodes RegisterCCEntryRes6 to BER format.
func (v *RegisterCCEntryRes6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RegisterCCEntryRes6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *RegisterCCEntryRes6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CcbsFeature != nil {
		enc_ccbsfeature, err := v.CcbsFeature.MarshalBER(opts...)
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-Feature: %w", err)
		}
		retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsfeature)
		if tagErr_enc_ccbsfeature != nil {
			return nil, fmt.Errorf("encoding ccbs-Feature: %w", tagErr_enc_ccbsfeature)
		}
		enc_ccbsfeature = retagged_enc_ccbsfeature
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes RegisterCCEntryRes6 to DER format.
func (v *RegisterCCEntryRes6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RegisterCCEntryRes6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CcbsFeature != nil {
		enc_ccbsfeature, err := v.CcbsFeature.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding ccbs-Feature: %w", err)
		}
		retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsfeature)
		if tagErr_enc_ccbsfeature != nil {
			return nil, fmt.Errorf("encoding ccbs-Feature: %w", tagErr_enc_ccbsfeature)
		}
		enc_ccbsfeature = retagged_enc_ccbsfeature
		children = append(children, enc_ccbsfeature...)
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
		return nil, fmt.Errorf("encoding RegisterCCEntryRes6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RegisterCCEntryRes6 from BER/DER format.
func (v *RegisterCCEntryRes6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: RegisterCCEntryRes6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = RegisterCCEntryRes6{}
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
		return fmt.Errorf("decoding RegisterCCEntryRes6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterCCEntryRes6", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ccbs-Feature
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
				decodedTag_ccbsfeature, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ccbs-Feature: %w", err)
				}
				if decodedTag_ccbsfeature.Class != tag.ClassContextSpecific || decodedTag_ccbsfeature.Number != 0 || decodedTag_ccbsfeature.Constructed != true {
					return fmt.Errorf("decoding ccbs-Feature: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsfeature)
				}
				reconstructed_ccbsfeature, reconstructionErr_ccbsfeature := ber.EncodeSequence(rawVal_ccbsfeature)
				if reconstructionErr_ccbsfeature != nil {
					return fmt.Errorf("decoding ccbs-Feature: %w", reconstructionErr_ccbsfeature)
				}
				var dec_ccbsfeature CCBSFeature6
				if unmErr := dec_ccbsfeature.UnmarshalBER(reconstructed_ccbsfeature, ber.ChildDecodeOptions(opts, "ccbsfeature")...); unmErr != nil {
					return fmt.Errorf("decoding ccbs-Feature: %w", unmErr)
				}
				v.CcbsFeature = &dec_ccbsfeature
				if offset < 0 || offset >
					len(content) || n_ccbsfeature < 0 || n_ccbsfeature > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsfeature
			}
		}
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterCCEntryRes6", Cause: extErr_}
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

// MarshalBER encodes EraseCCEntryArg6 to BER format.
func (v *EraseCCEntryArg6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EraseCCEntryArg6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EraseCCEntryArg6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.CcbsIndex != nil {
		if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
			if constraintErr := ber.CheckEncodedValue(opts, "ccbs-Index", "(1..5)", fmt.Sprint(int64(*v.CcbsIndex))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsindex := ber.EncodeInteger(int64(*v.CcbsIndex))
		retagged_enc_ccbsindex, tagErr_enc_ccbsindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ccbsindex)
		if tagErr_enc_ccbsindex != nil {
			return nil, fmt.Errorf("encoding ccbs-Index: %w", tagErr_enc_ccbsindex)
		}
		enc_ccbsindex = retagged_enc_ccbsindex
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes EraseCCEntryArg6 to DER format.
func (v *EraseCCEntryArg6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EraseCCEntryArg6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.CcbsIndex != nil {
		if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
			if constraintErr := ber.CheckEncodedValue(nil, "ccbs-Index", "(1..5)", fmt.Sprint(int64(*v.CcbsIndex))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsindex := ber.EncodeInteger(int64(*v.CcbsIndex))
		retagged_enc_ccbsindex, tagErr_enc_ccbsindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ccbsindex)
		if tagErr_enc_ccbsindex != nil {
			return nil, fmt.Errorf("encoding ccbs-Index: %w", tagErr_enc_ccbsindex)
		}
		enc_ccbsindex = retagged_enc_ccbsindex
		children = append(children, enc_ccbsindex...)
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
		return nil, fmt.Errorf("encoding EraseCCEntryArg6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EraseCCEntryArg6 from BER/DER format.
func (v *EraseCCEntryArg6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EraseCCEntryArg6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = EraseCCEntryArg6{}
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
		return fmt.Errorf("decoding EraseCCEntryArg6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EraseCCEntryArg6", Cause: ber.ErrExtraData}
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
	decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
		return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
	}
	decVal_sscode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sscode.Constructed, rawVal_sscode, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding ss-Code: %w", octetErr)
	}
	v.SsCode = SSCode6(decVal_sscode)
	if offset < 0 || offset >
		len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_sscode
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode ccbs-Index
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_ccbsindex, n_ccbsindex, rawVal_ccbsindex, err := ber.DecodeTLV(content[offset:], opts...)
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
				tmp_ccbsindex := CCBSIndex6(decVal_ccbsindex)
				v.CcbsIndex = &tmp_ccbsindex
				if offset < 0 || offset >
					len(content) || n_ccbsindex < 0 || n_ccbsindex > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsindex
				if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
					if constraintErr := ber.CheckDecodedValue(opts, "ccbs-Index", "(1..5)", fmt.Sprint(int64(*v.CcbsIndex))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "EraseCCEntryArg6", Cause: extErr_}
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

// MarshalBER encodes EraseCCEntryRes6 to BER format.
func (v *EraseCCEntryRes6) MarshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EraseCCEntryRes6 receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER(opts...)
	if err != nil {
		return nil, err
	}
	return ber.PreserveEncodedBER(encoded, v.berOriginal_, v.berSnapshot_, opts), nil
}
func (v *EraseCCEntryRes6) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
		}
		enc_ssstatus = retagged_enc_ssstatus
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
	return ber.EncodeSequence(children)
}

// MarshalDER encodes EraseCCEntryRes6 to DER format.
func (v *EraseCCEntryRes6) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EraseCCEntryRes6 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckEncodedLength(nil, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", encodeErr_enc_sscode)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, fmt.Errorf("encoding ss-Code: %w", tagErr_enc_sscode)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := ber.CheckEncodedLength(nil, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", encodeErr_enc_ssstatus)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, fmt.Errorf("encoding ss-Status: %w", tagErr_enc_ssstatus)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
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
		return nil, fmt.Errorf("encoding EraseCCEntryRes6 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EraseCCEntryRes6 from BER/DER format.
func (v *EraseCCEntryRes6) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if v == nil {
		return fmt.Errorf("%w: EraseCCEntryRes6 destination is nil", ber.ErrInvalidValue)
	}
	opts = ber.TrackBERForm(opts)
	if err := ber.ValidateBERElement(data, opts...); err != nil {
		return err
	}
	*v = EraseCCEntryRes6{}
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
		return fmt.Errorf("decoding EraseCCEntryRes6 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EraseCCEntryRes6", Cause: ber.ErrExtraData}
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
	decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
	if err != nil {
		return fmt.Errorf("decoding ss-Code: %w", err)
	}
	if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
		return fmt.Errorf("decoding ss-Code: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode)
	}
	decVal_sscode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sscode.Constructed, rawVal_sscode, opts...)
	if octetErr != nil {
		return fmt.Errorf("decoding ss-Code: %w", octetErr)
	}
	v.SsCode = SSCode6(decVal_sscode)
	if offset < 0 || offset >
		len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
		return fmt.Errorf("invalid BER content window")
	}

	offset += n_sscode
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := ber.CheckDecodedLength(opts, "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return constraintErr
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return fmt.Errorf("decoding ss-Status: %w", err)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 1 {
					return fmt.Errorf("decoding ss-Status: %w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return fmt.Errorf("decoding ss-Status: %w", octetErr)
				}
				tmp_ssstatus := SSStatus6(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := ber.CheckDecodedLength(opts, "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "EraseCCEntryRes6", Cause: extErr_}
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
