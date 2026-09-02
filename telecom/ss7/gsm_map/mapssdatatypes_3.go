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

	// MaxNumOfCCBSRequests3 is the integer constant for MaxNumOfCCBSRequests3.
	MaxNumOfCCBSRequests3 int64 = 5

	// MaxUSSDStringLength3 is the integer constant for MaxUSSDStringLength3.
	MaxUSSDStringLength3 int64 = 160

	// MaxNumOfSS3 is the integer constant for MaxNumOfSS3.
	MaxNumOfSS3 int64 = 30

	// MaxNumOfBasicServiceGroups3 is the integer constant for MaxNumOfBasicServiceGroups3.
	MaxNumOfBasicServiceGroups3 int64 = 13

	// MaxEventSpecification3 is the integer constant for MaxEventSpecification3.
	MaxEventSpecification3 int64 = 2
)

// RegisterSSArg3 represents the ASN.1 type RegisterSS-Arg (SEQUENCE).
type RegisterSSArg3 struct {
	SsCode                SSCode3                `asn1:""`
	BasicService          *BasicServiceCode3     `asn1:",optional" json:"BasicService,omitempty"`
	ForwardedToNumber     *AddressString3        `asn1:"tag:4,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString3 `asn1:"tag:6,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	NoReplyConditionTime  *NoReplyConditionTime3 `asn1:"tag:5,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	DefaultPriority       *EMLPPPriority3        `asn1:"tag:7,context,implicit,optional" json:"DefaultPriority,omitempty"`
	NbrUser               *MCBearers3            `asn1:"tag:8,context,implicit,optional" json:"NbrUser,omitempty"`
	LongFTNSupported      *struct{}              `asn1:"tag:9,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
}

// NoReplyConditionTime3 represents the ASN.1 type NoReplyConditionTime (INTEGER).
type NoReplyConditionTime3 = int64

// SSInfo3 choice constants.
const (
	SSInfo3ChoiceForwardingInfo  = 1
	SSInfo3ChoiceCallBarringInfo = 2
	SSInfo3ChoiceSsData          = 3
)

// SSInfo3 represents the ASN.1 CHOICE type SS-Info.
type SSInfo3 struct {
	Choice          int
	ForwardingInfo  *ForwardingInfo3  `json:"ForwardingInfo,omitempty"`
	CallBarringInfo *CallBarringInfo3 `json:"CallBarringInfo,omitempty"`
	SsData          *SSData3          `json:"SsData,omitempty"`
}

// NewSSInfo3ForwardingInfo creates a SSInfo3 with the forwardingInfo alternative.
func NewSSInfo3ForwardingInfo(v ForwardingInfo3) SSInfo3 {
	return SSInfo3{
		Choice:         SSInfo3ChoiceForwardingInfo,
		ForwardingInfo: &v,
	}
}

// NewSSInfo3CallBarringInfo creates a SSInfo3 with the callBarringInfo alternative.
func NewSSInfo3CallBarringInfo(v CallBarringInfo3) SSInfo3 {
	return SSInfo3{
		Choice:          SSInfo3ChoiceCallBarringInfo,
		CallBarringInfo: &v,
	}
}

// NewSSInfo3SsData creates a SSInfo3 with the ss-Data alternative.
func NewSSInfo3SsData(v SSData3) SSInfo3 {
	return SSInfo3{
		Choice: SSInfo3ChoiceSsData,
		SsData: &v,
	}
}

// ForwardingInfo3 represents the ASN.1 type ForwardingInfo (SEQUENCE).
type ForwardingInfo3 struct {
	SsCode                      *SSCode3               `asn1:",optional" json:"SsCode,omitempty"`
	ForwardingFeatureList       ForwardingFeatureList3 `asn1:""`
	ForwardingFeatureListIndef_ bool                   `asn1:"-" json:"-"`
	ExtCount_                   int64                  `asn1:"-" json:"-"`
	ExtPresent_                 []bool                 `asn1:"-" json:"-"`
	ExtData_                    [][]byte               `asn1:"-" json:"-"`
}

// ForwardingFeatureList3 represents the ASN.1 type ForwardingFeatureList (SEQUENCE_OF).
type ForwardingFeatureList3 = []ForwardingFeature3

// ForwardingFeature3 represents the ASN.1 type ForwardingFeature (SEQUENCE).
type ForwardingFeature3 struct {
	BasicService          *BasicServiceCode3     `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus              *SSStatus3             `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ForwardedToNumber     *ISDNAddressString3    `asn1:"tag:5,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *ISDNSubaddressString3 `asn1:"tag:8,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	ForwardingOptions     *ForwardingOptions3    `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	NoReplyConditionTime  *NoReplyConditionTime3 `asn1:"tag:7,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	LongForwardedToNumber *FTNAddressString3     `asn1:"tag:9,context,implicit,optional" json:"LongForwardedToNumber,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
}

// SSStatus3 represents the ASN.1 type SS-Status (OCTET_STRING).
type SSStatus3 = []byte

// ForwardingOptions3 represents the ASN.1 type ForwardingOptions (OCTET_STRING).
type ForwardingOptions3 = []byte

// CallBarringInfo3 represents the ASN.1 type CallBarringInfo (SEQUENCE).
type CallBarringInfo3 struct {
	SsCode                       *SSCode3                `asn1:",optional" json:"SsCode,omitempty"`
	CallBarringFeatureList       CallBarringFeatureList3 `asn1:""`
	CallBarringFeatureListIndef_ bool                    `asn1:"-" json:"-"`
	ExtCount_                    int64                   `asn1:"-" json:"-"`
	ExtPresent_                  []bool                  `asn1:"-" json:"-"`
	ExtData_                     [][]byte                `asn1:"-" json:"-"`
}

// CallBarringFeatureList3 represents the ASN.1 type CallBarringFeatureList (SEQUENCE_OF).
type CallBarringFeatureList3 = []CallBarringFeature3

// CallBarringFeature3 represents the ASN.1 type CallBarringFeature (SEQUENCE).
type CallBarringFeature3 struct {
	BasicService *BasicServiceCode3 `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSStatus3         `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64              `asn1:"-" json:"-"`
	ExtPresent_  []bool             `asn1:"-" json:"-"`
	ExtData_     [][]byte           `asn1:"-" json:"-"`
}

// SSData3 represents the ASN.1 type SS-Data (SEQUENCE).
type SSData3 struct {
	SsCode                      *SSCode3               `asn1:",optional" json:"SsCode,omitempty"`
	SsStatus                    *SSStatus3             `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	SsSubscriptionOption        *SSSubscriptionOption3 `asn1:",optional" json:"SsSubscriptionOption,omitempty"`
	BasicServiceGroupList       BasicServiceGroupList3 `asn1:",optional" json:"BasicServiceGroupList,omitempty"`
	BasicServiceGroupListIndef_ bool                   `asn1:"-" json:"-"`
	DefaultPriority             *EMLPPPriority3        `asn1:",optional" json:"DefaultPriority,omitempty"`
	NbrUser                     *MCBearers3            `asn1:"tag:5,context,implicit,optional" json:"NbrUser,omitempty"`
	ExtCount_                   int64                  `asn1:"-" json:"-"`
	ExtPresent_                 []bool                 `asn1:"-" json:"-"`
	ExtData_                    [][]byte               `asn1:"-" json:"-"`
}

// SSSubscriptionOption3 choice constants.
const (
	SSSubscriptionOption3ChoiceCliRestrictionOption = 1
	SSSubscriptionOption3ChoiceOverrideCategory     = 2
)

// SSSubscriptionOption3 represents the ASN.1 CHOICE type SS-SubscriptionOption.
type SSSubscriptionOption3 struct {
	Choice               int
	CliRestrictionOption *CliRestrictionOption3 `json:"CliRestrictionOption,omitempty"`
	OverrideCategory     *OverrideCategory3     `json:"OverrideCategory,omitempty"`
}

// NewSSSubscriptionOption3CliRestrictionOption creates a SSSubscriptionOption3 with the cliRestrictionOption alternative.
func NewSSSubscriptionOption3CliRestrictionOption(v CliRestrictionOption3) SSSubscriptionOption3 {
	return SSSubscriptionOption3{
		Choice:               SSSubscriptionOption3ChoiceCliRestrictionOption,
		CliRestrictionOption: &v,
	}
}

// NewSSSubscriptionOption3OverrideCategory creates a SSSubscriptionOption3 with the overrideCategory alternative.
func NewSSSubscriptionOption3OverrideCategory(v OverrideCategory3) SSSubscriptionOption3 {
	return SSSubscriptionOption3{
		Choice:           SSSubscriptionOption3ChoiceOverrideCategory,
		OverrideCategory: &v,
	}
}

// CliRestrictionOption3 represents the ASN.1 ENUMERATED type CliRestrictionOption.
type CliRestrictionOption3 int64

const (
	CliRestrictionOption3Permanent                  CliRestrictionOption3 = 0
	CliRestrictionOption3TemporaryDefaultRestricted CliRestrictionOption3 = 1
	CliRestrictionOption3TemporaryDefaultAllowed    CliRestrictionOption3 = 2
)

func (v CliRestrictionOption3) String() string {
	switch v {
	case CliRestrictionOption3Permanent:
		return "permanent"
	case CliRestrictionOption3TemporaryDefaultRestricted:
		return "temporaryDefaultRestricted"
	case CliRestrictionOption3TemporaryDefaultAllowed:
		return "temporaryDefaultAllowed"
	default:
		return "unknown"
	}
}

// OverrideCategory3 represents the ASN.1 ENUMERATED type OverrideCategory.
type OverrideCategory3 int64

const (
	OverrideCategory3OverrideEnabled  OverrideCategory3 = 0
	OverrideCategory3OverrideDisabled OverrideCategory3 = 1
)

func (v OverrideCategory3) String() string {
	switch v {
	case OverrideCategory3OverrideEnabled:
		return "overrideEnabled"
	case OverrideCategory3OverrideDisabled:
		return "overrideDisabled"
	default:
		return "unknown"
	}
}

// SSForBSCode3 represents the ASN.1 type SS-ForBS-Code (SEQUENCE).
type SSForBSCode3 struct {
	SsCode           SSCode3            `asn1:""`
	BasicService     *BasicServiceCode3 `asn1:",optional" json:"BasicService,omitempty"`
	LongFTNSupported *struct{}          `asn1:"tag:4,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_        int64              `asn1:"-" json:"-"`
	ExtPresent_      []bool             `asn1:"-" json:"-"`
	ExtData_         [][]byte           `asn1:"-" json:"-"`
}

// GenericServiceInfo3 represents the ASN.1 type GenericServiceInfo (SEQUENCE).
type GenericServiceInfo3 struct {
	SsStatus                SSStatus3              `asn1:""`
	CliRestrictionOption    *CliRestrictionOption3 `asn1:",optional" json:"CliRestrictionOption,omitempty"`
	MaximumEntitledPriority *EMLPPPriority3        `asn1:"tag:0,context,implicit,optional" json:"MaximumEntitledPriority,omitempty"`
	DefaultPriority         *EMLPPPriority3        `asn1:"tag:1,context,implicit,optional" json:"DefaultPriority,omitempty"`
	CcbsFeatureList         CCBSFeatureList3       `asn1:"tag:2,context,implicit,optional" json:"CcbsFeatureList,omitempty"`
	CcbsFeatureListIndef_   bool                   `asn1:"-" json:"-"`
	NbrSB                   *MaxMCBearers3         `asn1:"tag:3,context,implicit,optional" json:"NbrSB,omitempty"`
	NbrUser                 *MCBearers3            `asn1:"tag:4,context,implicit,optional" json:"NbrUser,omitempty"`
	NbrSN                   *MCBearers3            `asn1:"tag:5,context,implicit,optional" json:"NbrSN,omitempty"`
	ExtCount_               int64                  `asn1:"-" json:"-"`
	ExtPresent_             []bool                 `asn1:"-" json:"-"`
	ExtData_                [][]byte               `asn1:"-" json:"-"`
}

// CCBSFeatureList3 represents the ASN.1 type CCBS-FeatureList (SEQUENCE_OF).
type CCBSFeatureList3 = []CCBSFeature3

// CCBSFeature3 represents the ASN.1 type CCBS-Feature (SEQUENCE).
type CCBSFeature3 struct {
	CcbsIndex             *CCBSIndex3            `asn1:"tag:0,context,implicit,optional" json:"CcbsIndex,omitempty"`
	BSubscriberNumber     *ISDNAddressString3    `asn1:"tag:1,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	BSubscriberSubaddress *ISDNSubaddressString3 `asn1:"tag:2,context,implicit,optional" json:"BSubscriberSubaddress,omitempty"`
	BasicServiceGroup     *BasicServiceCode3     `asn1:"tag:3,context,explicit,optional" json:"BasicServiceGroup,omitempty"`
	ExtCount_             int64                  `asn1:"-" json:"-"`
	ExtPresent_           []bool                 `asn1:"-" json:"-"`
	ExtData_              [][]byte               `asn1:"-" json:"-"`
}

// CCBSIndex3 represents the ASN.1 type CCBS-Index (INTEGER).
type CCBSIndex3 = int64

// InterrogateSSRes3 choice constants.
const (
	InterrogateSSRes3ChoiceSsStatus              = 1
	InterrogateSSRes3ChoiceBasicServiceGroupList = 2
	InterrogateSSRes3ChoiceForwardingFeatureList = 3
	InterrogateSSRes3ChoiceGenericServiceInfo    = 4
)

// InterrogateSSRes3 represents the ASN.1 CHOICE type InterrogateSS-Res.
type InterrogateSSRes3 struct {
	Choice                int
	SsStatus              *SSStatus3             `json:"SsStatus,omitempty"`
	BasicServiceGroupList BasicServiceGroupList3 `json:"BasicServiceGroupList,omitempty"`
	ForwardingFeatureList ForwardingFeatureList3 `json:"ForwardingFeatureList,omitempty"`
	GenericServiceInfo    *GenericServiceInfo3   `json:"GenericServiceInfo,omitempty"`
}

// NewInterrogateSSRes3SsStatus creates a InterrogateSSRes3 with the ss-Status alternative.
func NewInterrogateSSRes3SsStatus(v SSStatus3) InterrogateSSRes3 {
	return InterrogateSSRes3{
		Choice:   InterrogateSSRes3ChoiceSsStatus,
		SsStatus: &v,
	}
}

// NewInterrogateSSRes3BasicServiceGroupList creates a InterrogateSSRes3 with the basicServiceGroupList alternative.
func NewInterrogateSSRes3BasicServiceGroupList(v BasicServiceGroupList3) InterrogateSSRes3 {
	return InterrogateSSRes3{
		Choice:                InterrogateSSRes3ChoiceBasicServiceGroupList,
		BasicServiceGroupList: v,
	}
}

// NewInterrogateSSRes3ForwardingFeatureList creates a InterrogateSSRes3 with the forwardingFeatureList alternative.
func NewInterrogateSSRes3ForwardingFeatureList(v ForwardingFeatureList3) InterrogateSSRes3 {
	return InterrogateSSRes3{
		Choice:                InterrogateSSRes3ChoiceForwardingFeatureList,
		ForwardingFeatureList: v,
	}
}

// NewInterrogateSSRes3GenericServiceInfo creates a InterrogateSSRes3 with the genericServiceInfo alternative.
func NewInterrogateSSRes3GenericServiceInfo(v GenericServiceInfo3) InterrogateSSRes3 {
	return InterrogateSSRes3{
		Choice:             InterrogateSSRes3ChoiceGenericServiceInfo,
		GenericServiceInfo: &v,
	}
}

// USSDArg3 represents the ASN.1 type USSD-Arg (SEQUENCE).
type USSDArg3 struct {
	UssdDataCodingScheme USSDDataCodingScheme3 `asn1:""`
	UssdString           USSDString3           `asn1:""`
	AlertingPattern      *AlertingPattern3     `asn1:",optional" json:"AlertingPattern,omitempty"`
	Msisdn               *ISDNAddressString3   `asn1:"tag:0,context,implicit,optional" json:"Msisdn,omitempty"`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	ExtData_             [][]byte              `asn1:"-" json:"-"`
}

// USSDRes3 represents the ASN.1 type USSD-Res (SEQUENCE).
type USSDRes3 struct {
	UssdDataCodingScheme USSDDataCodingScheme3 `asn1:""`
	UssdString           USSDString3           `asn1:""`
	ExtCount_            int64                 `asn1:"-" json:"-"`
	ExtPresent_          []bool                `asn1:"-" json:"-"`
	ExtData_             [][]byte              `asn1:"-" json:"-"`
}

// USSDDataCodingScheme3 represents the ASN.1 type USSD-DataCodingScheme (OCTET_STRING).
type USSDDataCodingScheme3 = []byte

// USSDString3 represents the ASN.1 type USSD-String (OCTET_STRING).
type USSDString3 = []byte

// Password3 represents the ASN.1 type Password (NumericString).
type Password3 = string

// GuidanceInfo3 represents the ASN.1 ENUMERATED type GuidanceInfo.
type GuidanceInfo3 int64

const (
	GuidanceInfo3EnterPW         GuidanceInfo3 = 0
	GuidanceInfo3EnterNewPW      GuidanceInfo3 = 1
	GuidanceInfo3EnterNewPWAgain GuidanceInfo3 = 2
)

func (v GuidanceInfo3) String() string {
	switch v {
	case GuidanceInfo3EnterPW:
		return "enterPW"
	case GuidanceInfo3EnterNewPW:
		return "enterNewPW"
	case GuidanceInfo3EnterNewPWAgain:
		return "enterNewPW-Again"
	default:
		return "unknown"
	}
}

// SSList3 represents the ASN.1 type SS-List (SEQUENCE_OF).
type SSList3 = []SSCode3

// SSInfoList3 represents the ASN.1 type SS-InfoList (SEQUENCE_OF).
type SSInfoList3 = []SSInfo3

// BasicServiceGroupList3 represents the ASN.1 type BasicServiceGroupList (SEQUENCE_OF).
type BasicServiceGroupList3 = []BasicServiceCode3

// SSInvocationNotificationArg3 represents the ASN.1 type SS-InvocationNotificationArg (SEQUENCE).
type SSInvocationNotificationArg3 struct {
	Imsi                       IMSI3                 `asn1:"tag:0,context,implicit"`
	Msisdn                     ISDNAddressString3    `asn1:"tag:1,context,implicit"`
	SsEvent                    SSCode3               `asn1:"tag:2,context,implicit"`
	SsEventSpecification       SSEventSpecification3 `asn1:"tag:3,context,implicit,optional" json:"SsEventSpecification,omitempty"`
	SsEventSpecificationIndef_ bool                  `asn1:"-" json:"-"`
	ExtensionContainer         *ExtensionContainer3  `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	BSubscriberNumber          *ISDNAddressString3   `asn1:"tag:5,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	CcbsRequestState           *CCBSRequestState3    `asn1:"tag:6,context,implicit,optional" json:"CcbsRequestState,omitempty"`
	ExtCount_                  int64                 `asn1:"-" json:"-"`
	ExtPresent_                []bool                `asn1:"-" json:"-"`
	ExtData_                   [][]byte              `asn1:"-" json:"-"`
}

// CCBSRequestState3 represents the ASN.1 ENUMERATED type CCBS-RequestState.
type CCBSRequestState3 int64

const (
	CCBSRequestState3Request   CCBSRequestState3 = 0
	CCBSRequestState3Recall    CCBSRequestState3 = 1
	CCBSRequestState3Active    CCBSRequestState3 = 2
	CCBSRequestState3Completed CCBSRequestState3 = 3
	CCBSRequestState3Suspended CCBSRequestState3 = 4
	CCBSRequestState3Frozen    CCBSRequestState3 = 5
	CCBSRequestState3Deleted   CCBSRequestState3 = 6
)

func (v CCBSRequestState3) String() string {
	switch v {
	case CCBSRequestState3Request:
		return "request"
	case CCBSRequestState3Recall:
		return "recall"
	case CCBSRequestState3Active:
		return "active"
	case CCBSRequestState3Completed:
		return "completed"
	case CCBSRequestState3Suspended:
		return "suspended"
	case CCBSRequestState3Frozen:
		return "frozen"
	case CCBSRequestState3Deleted:
		return "deleted"
	default:
		return "unknown"
	}
}

// SSInvocationNotificationRes3 represents the ASN.1 type SS-InvocationNotificationRes (SEQUENCE).
type SSInvocationNotificationRes3 struct {
	ExtensionContainer *ExtensionContainer3 `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                `asn1:"-" json:"-"`
	ExtPresent_        []bool               `asn1:"-" json:"-"`
	ExtData_           [][]byte             `asn1:"-" json:"-"`
}

// SSEventSpecification3 represents the ASN.1 type SS-EventSpecification (SEQUENCE_OF).
type SSEventSpecification3 = []AddressString3

// RegisterCCEntryArg3 represents the ASN.1 type RegisterCC-EntryArg (SEQUENCE).
type RegisterCCEntryArg3 struct {
	SsCode      SSCode3    `asn1:"tag:0,context,implicit"`
	CcbsData    *CCBSData3 `asn1:"tag:1,context,implicit,optional" json:"CcbsData,omitempty"`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	ExtData_    [][]byte   `asn1:"-" json:"-"`
}

// CCBSData3 represents the ASN.1 type CCBS-Data (SEQUENCE).
type CCBSData3 struct {
	CcbsFeature       CCBSFeature3        `asn1:"tag:0,context,implicit"`
	TranslatedBNumber ISDNAddressString3  `asn1:"tag:1,context,implicit"`
	ServiceIndicator  *ServiceIndicator3  `asn1:"tag:2,context,implicit,optional" json:"ServiceIndicator,omitempty"`
	CallInfo          ExternalSignalInfo3 `asn1:"tag:3,context,implicit"`
	NetworkSignalInfo ExternalSignalInfo3 `asn1:"tag:4,context,implicit"`
	ExtCount_         int64               `asn1:"-" json:"-"`
	ExtPresent_       []bool              `asn1:"-" json:"-"`
	ExtData_          [][]byte            `asn1:"-" json:"-"`
}

// ServiceIndicator3 represents the ASN.1 type ServiceIndicator (BIT_STRING).
type ServiceIndicator3 = runtime.BitString

// RegisterCCEntryRes3 represents the ASN.1 type RegisterCC-EntryRes (SEQUENCE).
type RegisterCCEntryRes3 struct {
	CcbsFeature *CCBSFeature3 `asn1:"tag:0,context,implicit,optional" json:"CcbsFeature,omitempty"`
	ExtCount_   int64         `asn1:"-" json:"-"`
	ExtPresent_ []bool        `asn1:"-" json:"-"`
	ExtData_    [][]byte      `asn1:"-" json:"-"`
}

// EraseCCEntryArg3 represents the ASN.1 type EraseCC-EntryArg (SEQUENCE).
type EraseCCEntryArg3 struct {
	SsCode      SSCode3     `asn1:"tag:0,context,implicit"`
	CcbsIndex   *CCBSIndex3 `asn1:"tag:1,context,implicit,optional" json:"CcbsIndex,omitempty"`
	ExtCount_   int64       `asn1:"-" json:"-"`
	ExtPresent_ []bool      `asn1:"-" json:"-"`
	ExtData_    [][]byte    `asn1:"-" json:"-"`
}

// EraseCCEntryRes3 represents the ASN.1 type EraseCC-EntryRes (SEQUENCE).
type EraseCCEntryRes3 struct {
	SsCode      SSCode3    `asn1:"tag:0,context,implicit"`
	SsStatus    *SSStatus3 `asn1:"tag:1,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_   int64      `asn1:"-" json:"-"`
	ExtPresent_ []bool     `asn1:"-" json:"-"`
	ExtData_    [][]byte   `asn1:"-" json:"-"`
}

// MarshalBER encodes RegisterSSArg3 to BER format.
func (v *RegisterSSArg3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes RegisterSSArg3 to DER format.
func (v *RegisterSSArg3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding RegisterSSArg3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RegisterSSArg3 from BER/DER format.
func (v *RegisterSSArg3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RegisterSSArg3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterSSArg3", Cause: ber.ErrExtraData}
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
	v.SsCode = SSCode3(val_sscode)
	offset += n
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode3)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode3
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
				tmp_forwardedtonumber := AddressString3(rawVal_forwardedtonumber)
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
				tmp_forwardedtosubaddress := ISDNSubaddressString3(rawVal_forwardedtosubaddress)
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
				tmp_noreplyconditiontime := NoReplyConditionTime3(decVal_noreplyconditiontime)
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
				tmp_defaultpriority := EMLPPPriority3(decVal_defaultpriority)
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
				tmp_nbruser := MCBearers3(decVal_nbruser)
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
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterSSArg3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSInfo3 to BER format.
func (v *SSInfo3) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SSInfo3ChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("choice SSInfo3: forwardingInfo is nil")
		}
		enc_0, err := v.ForwardingInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingInfo: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case SSInfo3ChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("choice SSInfo3: callBarringInfo is nil")
		}
		enc_1, err := v.CallBarringInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding callBarringInfo: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		return enc_1, nil
	case SSInfo3ChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("choice SSInfo3: ss-Data is nil")
		}
		enc_2, err := v.SsData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ss-Data: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSInfo3", v.Choice)
	}
}

// MarshalDER encodes SSInfo3 to DER format.
func (v *SSInfo3) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case SSInfo3ChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("choice SSInfo3: forwardingInfo is nil")
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
	case SSInfo3ChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("choice SSInfo3: callBarringInfo is nil")
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
	case SSInfo3ChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("choice SSInfo3: ss-Data is nil")
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
		return nil, fmt.Errorf("encoding SSInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSInfo3 from BER/DER format.
func (v *SSInfo3) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSInfo3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSInfo3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SSInfo3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInfo3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = SSInfo3ChoiceForwardingInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding forwardingInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec ForwardingInfo3
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding forwardingInfo: %w", unmErr)
		}
		v.ForwardingInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = SSInfo3ChoiceCallBarringInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding callBarringInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec CallBarringInfo3
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding callBarringInfo: %w", unmErr)
		}
		v.CallBarringInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = SSInfo3ChoiceSsData
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ss-Data: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SSData3
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding ss-Data: %w", unmErr)
		}
		v.SsData = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SSInfo3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes ForwardingInfo3 to BER format.
func (v *ForwardingInfo3) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		children = append(children, enc_sscode...)
	}
	enc_forwardingfeaturelist, err := MarshalBERForwardingFeatureList3(v.ForwardingFeatureList)
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

// MarshalDER encodes ForwardingInfo3 to DER format.
func (v *ForwardingInfo3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ForwardingInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingInfo3 from BER/DER format.
func (v *ForwardingInfo3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardingInfo3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingInfo3", Cause: ber.ErrExtraData}
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
				tmp_sscode := SSCode3(val_sscode)
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
	// Decode nested SEQUENCE_OF (ForwardingFeatureList3)
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
	dec_forwardingfeaturelist, unmErr := UnmarshalBERForwardingFeatureList3(tlv_forwardingfeaturelist)
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingInfo3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERForwardingFeatureList3 encodes a ForwardingFeatureList3 list to BER.
func MarshalBERForwardingFeatureList3(list ForwardingFeatureList3) ([]byte, error) {
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

// UnmarshalBERForwardingFeatureList3 decodes a ForwardingFeatureList3 list from BER.
func UnmarshalBERForwardingFeatureList3(data []byte) (ForwardingFeatureList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding ForwardingFeatureList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "ForwardingFeatureList3", Cause: ber.ErrExtraData}
	}
	var result ForwardingFeatureList3
	offset := 0
	for offset < len(content) {
		var elem ForwardingFeature3
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

// MarshalBER encodes ForwardingFeature3 to BER format.
func (v *ForwardingFeature3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes ForwardingFeature3 to DER format.
func (v *ForwardingFeature3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding ForwardingFeature3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes ForwardingFeature3 from BER/DER format.
func (v *ForwardingFeature3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding ForwardingFeature3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardingFeature3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode3)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode3
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
				tmp_ssstatus := SSStatus3(rawVal_ssstatus)
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
				tmp_forwardedtonumber := ISDNAddressString3(rawVal_forwardedtonumber)
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
				tmp_forwardedtosubaddress := ISDNSubaddressString3(rawVal_forwardedtosubaddress)
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
				tmp_forwardingoptions := ForwardingOptions3(rawVal_forwardingoptions)
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
				tmp_noreplyconditiontime := NoReplyConditionTime3(decVal_noreplyconditiontime)
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
				tmp_longforwardedtonumber := FTNAddressString3(rawVal_longforwardedtonumber)
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
			return &ber.DecodeError{Offset: offset, TypeName: "ForwardingFeature3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CallBarringInfo3 to BER format.
func (v *CallBarringInfo3) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		children = append(children, enc_sscode...)
	}
	enc_callbarringfeaturelist, err := MarshalBERCallBarringFeatureList3(v.CallBarringFeatureList)
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

// MarshalDER encodes CallBarringInfo3 to DER format.
func (v *CallBarringInfo3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CallBarringInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CallBarringInfo3 from BER/DER format.
func (v *CallBarringInfo3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CallBarringInfo3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarringInfo3", Cause: ber.ErrExtraData}
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
				tmp_sscode := SSCode3(val_sscode)
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
	// Decode nested SEQUENCE_OF (CallBarringFeatureList3)
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
	dec_callbarringfeaturelist, unmErr := UnmarshalBERCallBarringFeatureList3(tlv_callbarringfeaturelist)
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
			return &ber.DecodeError{Offset: offset, TypeName: "CallBarringInfo3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERCallBarringFeatureList3 encodes a CallBarringFeatureList3 list to BER.
func MarshalBERCallBarringFeatureList3(list CallBarringFeatureList3) ([]byte, error) {
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

// UnmarshalBERCallBarringFeatureList3 decodes a CallBarringFeatureList3 list from BER.
func UnmarshalBERCallBarringFeatureList3(data []byte) (CallBarringFeatureList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding CallBarringFeatureList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CallBarringFeatureList3", Cause: ber.ErrExtraData}
	}
	var result CallBarringFeatureList3
	offset := 0
	for offset < len(content) {
		var elem CallBarringFeature3
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

// MarshalBER encodes CallBarringFeature3 to BER format.
func (v *CallBarringFeature3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CallBarringFeature3 to DER format.
func (v *CallBarringFeature3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CallBarringFeature3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CallBarringFeature3 from BER/DER format.
func (v *CallBarringFeature3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CallBarringFeature3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CallBarringFeature3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode3)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode3
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
				tmp_ssstatus := SSStatus3(rawVal_ssstatus)
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
			return &ber.DecodeError{Offset: offset, TypeName: "CallBarringFeature3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSData3 to BER format.
func (v *SSData3) MarshalBER() ([]byte, error) {
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
		enc_basicservicegrouplist, err := MarshalBERBasicServiceGroupList3(v.BasicServiceGroupList)
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

// MarshalDER encodes SSData3 to DER format.
func (v *SSData3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SSData3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSData3 from BER/DER format.
func (v *SSData3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSData3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSData3", Cause: ber.ErrExtraData}
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
				tmp_sscode := SSCode3(val_sscode)
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
				tmp_ssstatus := SSStatus3(rawVal_ssstatus)
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
				// Decode nested CHOICE (SSSubscriptionOption3)
				_, n_sssubscriptionoption, _, tlvErr_sssubscriptionoption := ber.DecodeTLV(content[offset:])
				if tlvErr_sssubscriptionoption != nil {
					return fmt.Errorf("decoding ss-SubscriptionOption: %w", tlvErr_sssubscriptionoption)
				}
				var dec_sssubscriptionoption SSSubscriptionOption3
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
				// Decode nested SEQUENCE_OF (BasicServiceGroupList3)
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
				dec_basicservicegrouplist, unmErr := UnmarshalBERBasicServiceGroupList3(tlv_basicservicegrouplist)
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
				tmp_defaultpriority := EMLPPPriority3(val_defaultpriority)
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
				tmp_nbruser := MCBearers3(decVal_nbruser)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSData3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSSubscriptionOption3 to BER format.
func (v *SSSubscriptionOption3) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SSSubscriptionOption3ChoiceCliRestrictionOption:
		if v.CliRestrictionOption == nil {
			return nil, fmt.Errorf("choice SSSubscriptionOption3: cliRestrictionOption is nil")
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_0)
		return enc_0, nil
	case SSSubscriptionOption3ChoiceOverrideCategory:
		if v.OverrideCategory == nil {
			return nil, fmt.Errorf("choice SSSubscriptionOption3: overrideCategory is nil")
		}
		enc_1 := ber.EncodeEnumerated(int64(*v.OverrideCategory))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSSubscriptionOption3", v.Choice)
	}
}

// MarshalDER encodes SSSubscriptionOption3 to DER format.
func (v *SSSubscriptionOption3) MarshalDER() ([]byte, error) {
	encoded, err := v.MarshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDERElement(encoded); err != nil {
		return nil, fmt.Errorf("encoding SSSubscriptionOption3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSSubscriptionOption3 from BER/DER format.
func (v *SSSubscriptionOption3) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSSubscriptionOption3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSSubscriptionOption3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SSSubscriptionOption3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSubscriptionOption3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOption3ChoiceCliRestrictionOption
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cliRestrictionOption: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding cliRestrictionOption: %w", intErr)
		}
		tmp := CliRestrictionOption3(decVal)
		v.CliRestrictionOption = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOption3ChoiceOverrideCategory
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding overrideCategory: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding overrideCategory: %w", intErr)
		}
		tmp := OverrideCategory3(decVal)
		v.OverrideCategory = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SSSubscriptionOption3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SSForBSCode3 to BER format.
func (v *SSForBSCode3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSForBSCode3 to DER format.
func (v *SSForBSCode3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SSForBSCode3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSForBSCode3 from BER/DER format.
func (v *SSForBSCode3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSForBSCode3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSForBSCode3", Cause: ber.ErrExtraData}
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
	v.SsCode = SSCode3(val_sscode)
	offset += n
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (BasicServiceCode3)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice BasicServiceCode3
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSForBSCode3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes GenericServiceInfo3 to BER format.
func (v *GenericServiceInfo3) MarshalBER() ([]byte, error) {
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
		enc_ccbsfeaturelist, err := MarshalBERCCBSFeatureList3(v.CcbsFeatureList)
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

// MarshalDER encodes GenericServiceInfo3 to DER format.
func (v *GenericServiceInfo3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding GenericServiceInfo3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes GenericServiceInfo3 from BER/DER format.
func (v *GenericServiceInfo3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding GenericServiceInfo3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "GenericServiceInfo3", Cause: ber.ErrExtraData}
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
	v.SsStatus = SSStatus3(val_ssstatus)
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
				tmp_clirestrictionoption := CliRestrictionOption3(val_clirestrictionoption)
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
				tmp_maximumentitledpriority := EMLPPPriority3(decVal_maximumentitledpriority)
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
				tmp_defaultpriority := EMLPPPriority3(decVal_defaultpriority)
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
				dec_ccbsfeaturelist, unmErr := UnmarshalBERCCBSFeatureList3(reconstructed_ccbsfeaturelist)
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
				tmp_nbrsb := MaxMCBearers3(decVal_nbrsb)
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
				tmp_nbruser := MCBearers3(decVal_nbruser)
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
				tmp_nbrsn := MCBearers3(decVal_nbrsn)
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
			return &ber.DecodeError{Offset: offset, TypeName: "GenericServiceInfo3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERCCBSFeatureList3 encodes a CCBSFeatureList3 list to BER.
func MarshalBERCCBSFeatureList3(list CCBSFeatureList3) ([]byte, error) {
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

// UnmarshalBERCCBSFeatureList3 decodes a CCBSFeatureList3 list from BER.
func UnmarshalBERCCBSFeatureList3(data []byte) (CCBSFeatureList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding CCBSFeatureList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "CCBSFeatureList3", Cause: ber.ErrExtraData}
	}
	var result CCBSFeatureList3
	offset := 0
	for offset < len(content) {
		var elem CCBSFeature3
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

// MarshalBER encodes CCBSFeature3 to BER format.
func (v *CCBSFeature3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CCBSFeature3 to DER format.
func (v *CCBSFeature3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CCBSFeature3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CCBSFeature3 from BER/DER format.
func (v *CCBSFeature3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CCBSFeature3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CCBSFeature3", Cause: ber.ErrExtraData}
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
				tmp_ccbsindex := CCBSIndex3(decVal_ccbsindex)
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
				tmp_bsubscribernumber := ISDNAddressString3(rawVal_bsubscribernumber)
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
				tmp_bsubscribersubaddress := ISDNSubaddressString3(rawVal_bsubscribersubaddress)
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
				var dec_basicservicegroup BasicServiceCode3
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
			return &ber.DecodeError{Offset: offset, TypeName: "CCBSFeature3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes InterrogateSSRes3 to BER format.
func (v *InterrogateSSRes3) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case InterrogateSSRes3ChoiceSsStatus:
		if v.SsStatus == nil {
			return nil, fmt.Errorf("choice InterrogateSSRes3: ss-Status is nil")
		}
		enc_0 := ber.EncodeOctetString([]byte(*v.SsStatus))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case InterrogateSSRes3ChoiceBasicServiceGroupList:
		enc_1, err := MarshalBERBasicServiceGroupList3(v.BasicServiceGroupList)
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_1)
		return enc_1, nil
	case InterrogateSSRes3ChoiceForwardingFeatureList:
		enc_2, err := MarshalBERForwardingFeatureList3(v.ForwardingFeatureList)
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingFeatureList: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	case InterrogateSSRes3ChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("choice InterrogateSSRes3: genericServiceInfo is nil")
		}
		enc_3, err := v.GenericServiceInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for InterrogateSSRes3", v.Choice)
	}
}

// MarshalDER encodes InterrogateSSRes3 to DER format.
func (v *InterrogateSSRes3) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case InterrogateSSRes3ChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("choice InterrogateSSRes3: genericServiceInfo is nil")
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
		return nil, fmt.Errorf("encoding InterrogateSSRes3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes InterrogateSSRes3 from BER/DER format.
func (v *InterrogateSSRes3) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for InterrogateSSRes3 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InterrogateSSRes3: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding InterrogateSSRes3 CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InterrogateSSRes3", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = InterrogateSSRes3ChoiceSsStatus
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ss-Status: %w", tlvErr)
		}
		tmp := SSStatus3(rawVal)
		v.SsStatus = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = InterrogateSSRes3ChoiceBasicServiceGroupList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding basicServiceGroupList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERBasicServiceGroupList3(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding basicServiceGroupList: %w", unmErr)
		}
		v.BasicServiceGroupList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = InterrogateSSRes3ChoiceForwardingFeatureList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding forwardingFeatureList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERForwardingFeatureList3(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding forwardingFeatureList: %w", unmErr)
		}
		v.ForwardingFeatureList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = InterrogateSSRes3ChoiceGenericServiceInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding genericServiceInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec GenericServiceInfo3
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding genericServiceInfo: %w", unmErr)
		}
		v.GenericServiceInfo = &dec
	} else {
		return fmt.Errorf("unknown tag %s for InterrogateSSRes3 CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes USSDArg3 to BER format.
func (v *USSDArg3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes USSDArg3 to DER format.
func (v *USSDArg3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding USSDArg3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes USSDArg3 from BER/DER format.
func (v *USSDArg3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding USSDArg3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "USSDArg3", Cause: ber.ErrExtraData}
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
	v.UssdDataCodingScheme = USSDDataCodingScheme3(val_ussddatacodingscheme)
	offset += n
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	val_ussdstring, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ussd-String: %w", err)
	}
	v.UssdString = USSDString3(val_ussdstring)
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
				tmp_alertingpattern := AlertingPattern3(val_alertingpattern)
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
				tmp_msisdn := ISDNAddressString3(rawVal_msisdn)
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
			return &ber.DecodeError{Offset: offset, TypeName: "USSDArg3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes USSDRes3 to BER format.
func (v *USSDRes3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes USSDRes3 to DER format.
func (v *USSDRes3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding USSDRes3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes USSDRes3 from BER/DER format.
func (v *USSDRes3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding USSDRes3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "USSDRes3", Cause: ber.ErrExtraData}
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
	v.UssdDataCodingScheme = USSDDataCodingScheme3(val_ussddatacodingscheme)
	offset += n
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	val_ussdstring, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ussd-String: %w", err)
	}
	v.UssdString = USSDString3(val_ussdstring)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "USSDRes3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSSList3 encodes a SSList3 list to BER.
func MarshalBERSSList3(list SSList3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSSList3 decodes a SSList3 list from BER.
func UnmarshalBERSSList3(data []byte) (SSList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSList3", Cause: ber.ErrExtraData}
	}
	var result SSList3
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, SSCode3(val))
		offset += n
	}
	return result, nil
}

// MarshalBERSSInfoList3 encodes a SSInfoList3 list to BER.
func MarshalBERSSInfoList3(list SSInfoList3) ([]byte, error) {
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

// UnmarshalBERSSInfoList3 decodes a SSInfoList3 list from BER.
func UnmarshalBERSSInfoList3(data []byte) (SSInfoList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSInfoList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSInfoList3", Cause: ber.ErrExtraData}
	}
	var result SSInfoList3
	offset := 0
	for offset < len(content) {
		var elem SSInfo3
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

// MarshalBERBasicServiceGroupList3 encodes a BasicServiceGroupList3 list to BER.
func MarshalBERBasicServiceGroupList3(list BasicServiceGroupList3) ([]byte, error) {
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

// UnmarshalBERBasicServiceGroupList3 decodes a BasicServiceGroupList3 list from BER.
func UnmarshalBERBasicServiceGroupList3(data []byte) (BasicServiceGroupList3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding BasicServiceGroupList3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "BasicServiceGroupList3", Cause: ber.ErrExtraData}
	}
	var result BasicServiceGroupList3
	offset := 0
	for offset < len(content) {
		var elem BasicServiceCode3
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

// MarshalBER encodes SSInvocationNotificationArg3 to BER format.
func (v *SSInvocationNotificationArg3) MarshalBER() ([]byte, error) {
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
		enc_sseventspecification, err := MarshalBERSSEventSpecification3(v.SsEventSpecification)
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

// MarshalDER encodes SSInvocationNotificationArg3 to DER format.
func (v *SSInvocationNotificationArg3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SSInvocationNotificationArg3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSInvocationNotificationArg3 from BER/DER format.
func (v *SSInvocationNotificationArg3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSInvocationNotificationArg3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInvocationNotificationArg3", Cause: ber.ErrExtraData}
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
	v.Imsi = IMSI3(rawVal_imsi)
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
	v.Msisdn = ISDNAddressString3(rawVal_msisdn)
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
	v.SsEvent = SSCode3(rawVal_ssevent)
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
				dec_sseventspecification, unmErr := UnmarshalBERSSEventSpecification3(reconstructed_sseventspecification)
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
				var dec_extensioncontainer ExtensionContainer3
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
				tmp_bsubscribernumber := ISDNAddressString3(rawVal_bsubscribernumber)
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
				tmp_ccbsrequeststate := CCBSRequestState3(decVal_ccbsrequeststate)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSInvocationNotificationArg3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSInvocationNotificationRes3 to BER format.
func (v *SSInvocationNotificationRes3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSInvocationNotificationRes3 to DER format.
func (v *SSInvocationNotificationRes3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding SSInvocationNotificationRes3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes SSInvocationNotificationRes3 from BER/DER format.
func (v *SSInvocationNotificationRes3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSInvocationNotificationRes3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInvocationNotificationRes3", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionContainer3)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionContainer3
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSInvocationNotificationRes3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSSEventSpecification3 encodes a SSEventSpecification3 list to BER.
func MarshalBERSSEventSpecification3(list SSEventSpecification3) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSSEventSpecification3 decodes a SSEventSpecification3 list from BER.
func UnmarshalBERSSEventSpecification3(data []byte) (SSEventSpecification3, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSEventSpecification3: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSEventSpecification3", Cause: ber.ErrExtraData}
	}
	var result SSEventSpecification3
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, AddressString3(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes RegisterCCEntryArg3 to BER format.
func (v *RegisterCCEntryArg3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes RegisterCCEntryArg3 to DER format.
func (v *RegisterCCEntryArg3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding RegisterCCEntryArg3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RegisterCCEntryArg3 from BER/DER format.
func (v *RegisterCCEntryArg3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RegisterCCEntryArg3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterCCEntryArg3", Cause: ber.ErrExtraData}
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
	v.SsCode = SSCode3(rawVal_sscode)
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
				var dec_ccbsdata CCBSData3
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
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterCCEntryArg3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes CCBSData3 to BER format.
func (v *CCBSData3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes CCBSData3 to DER format.
func (v *CCBSData3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding CCBSData3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes CCBSData3 from BER/DER format.
func (v *CCBSData3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding CCBSData3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CCBSData3", Cause: ber.ErrExtraData}
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
	v.TranslatedBNumber = ISDNAddressString3(rawVal_translatedbnumber)
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
			return &ber.DecodeError{Offset: offset, TypeName: "CCBSData3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes RegisterCCEntryRes3 to BER format.
func (v *RegisterCCEntryRes3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes RegisterCCEntryRes3 to DER format.
func (v *RegisterCCEntryRes3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding RegisterCCEntryRes3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes RegisterCCEntryRes3 from BER/DER format.
func (v *RegisterCCEntryRes3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding RegisterCCEntryRes3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterCCEntryRes3", Cause: ber.ErrExtraData}
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
				var dec_ccbsfeature CCBSFeature3
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
			return &ber.DecodeError{Offset: offset, TypeName: "RegisterCCEntryRes3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EraseCCEntryArg3 to BER format.
func (v *EraseCCEntryArg3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes EraseCCEntryArg3 to DER format.
func (v *EraseCCEntryArg3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding EraseCCEntryArg3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EraseCCEntryArg3 from BER/DER format.
func (v *EraseCCEntryArg3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EraseCCEntryArg3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EraseCCEntryArg3", Cause: ber.ErrExtraData}
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
	v.SsCode = SSCode3(rawVal_sscode)
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
				tmp_ccbsindex := CCBSIndex3(decVal_ccbsindex)
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
			return &ber.DecodeError{Offset: offset, TypeName: "EraseCCEntryArg3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes EraseCCEntryRes3 to BER format.
func (v *EraseCCEntryRes3) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes EraseCCEntryRes3 to DER format.
func (v *EraseCCEntryRes3) MarshalDER() ([]byte, error) {
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
		return nil, fmt.Errorf("encoding EraseCCEntryRes3 as DER: %w", err)
	}
	return encoded, nil
}

// UnmarshalBER decodes EraseCCEntryRes3 from BER/DER format.
func (v *EraseCCEntryRes3) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding EraseCCEntryRes3 SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EraseCCEntryRes3", Cause: ber.ErrExtraData}
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
	v.SsCode = SSCode3(rawVal_sscode)
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
				tmp_ssstatus := SSStatus3(rawVal_ssstatus)
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
			return &ber.DecodeError{Offset: offset, TypeName: "EraseCCEntryRes3", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
