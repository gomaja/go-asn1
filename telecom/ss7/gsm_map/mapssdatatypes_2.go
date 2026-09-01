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

	// SSMaxNumOfCCBSRequests is the integer constant for SSMaxNumOfCCBSRequests.
	SSMaxNumOfCCBSRequests int64 = 5

	// SSMaxUSSDStringLength is the integer constant for SSMaxUSSDStringLength.
	SSMaxUSSDStringLength int64 = 160

	// SSMaxNumOfSS is the integer constant for SSMaxNumOfSS.
	SSMaxNumOfSS int64 = 30

	// SSMaxNumOfBasicServiceGroups is the integer constant for SSMaxNumOfBasicServiceGroups.
	SSMaxNumOfBasicServiceGroups int64 = 13

	// SSMaxEventSpecification is the integer constant for SSMaxEventSpecification.
	SSMaxEventSpecification int64 = 2
)

// SSRegisterSSArg represents the ASN.1 type SSRegisterSSArg (SEQUENCE).
type SSRegisterSSArg struct {
	SsCode                SSSSCode                             `asn1:""`
	BasicService          *CommonDataTypesBasicServiceCode     `asn1:",optional" json:"BasicService,omitempty"`
	ForwardedToNumber     *CommonDataTypesAddressString        `asn1:"tag:4,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *CommonDataTypesISDNSubaddressString `asn1:"tag:6,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	NoReplyConditionTime  *SSNoReplyConditionTime              `asn1:"tag:5,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	DefaultPriority       *CommonDataTypesEMLPPPriority        `asn1:"tag:7,context,implicit,optional" json:"DefaultPriority,omitempty"`
	NbrUser               *CommonDataTypesMCBearers            `asn1:"tag:8,context,implicit,optional" json:"NbrUser,omitempty"`
	LongFTNSupported      *struct{}                            `asn1:"tag:9,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_             int64                                `asn1:"-" json:"-"`
	ExtPresent_           []bool                               `asn1:"-" json:"-"`
	ExtData_              [][]byte                             `asn1:"-" json:"-"`
}

// SSNoReplyConditionTime represents the ASN.1 type SSNoReplyConditionTime (INTEGER).
type SSNoReplyConditionTime = int64

// SSSSInfo choice constants.
const (
	SSSSInfoChoiceForwardingInfo  = 1
	SSSSInfoChoiceCallBarringInfo = 2
	SSSSInfoChoiceSsData          = 3
)

// SSSSInfo represents the ASN.1 CHOICE type SSSSInfo.
type SSSSInfo struct {
	Choice          int
	ForwardingInfo  *SSForwardingInfo  `json:"ForwardingInfo,omitempty"`
	CallBarringInfo *SSCallBarringInfo `json:"CallBarringInfo,omitempty"`
	SsData          *SSSSData          `json:"SsData,omitempty"`
}

// NewSSSSInfoForwardingInfo creates a SSSSInfo with the forwardingInfo alternative.
func NewSSSSInfoForwardingInfo(v SSForwardingInfo) SSSSInfo {
	return SSSSInfo{
		Choice:         SSSSInfoChoiceForwardingInfo,
		ForwardingInfo: &v,
	}
}

// NewSSSSInfoCallBarringInfo creates a SSSSInfo with the callBarringInfo alternative.
func NewSSSSInfoCallBarringInfo(v SSCallBarringInfo) SSSSInfo {
	return SSSSInfo{
		Choice:          SSSSInfoChoiceCallBarringInfo,
		CallBarringInfo: &v,
	}
}

// NewSSSSInfoSsData creates a SSSSInfo with the ss-Data alternative.
func NewSSSSInfoSsData(v SSSSData) SSSSInfo {
	return SSSSInfo{
		Choice: SSSSInfoChoiceSsData,
		SsData: &v,
	}
}

// SSForwardingInfo represents the ASN.1 type SSForwardingInfo (SEQUENCE).
type SSForwardingInfo struct {
	SsCode                      *SSSSCode               `asn1:",optional" json:"SsCode,omitempty"`
	ForwardingFeatureList       SSForwardingFeatureList `asn1:""`
	ForwardingFeatureListIndef_ bool                    `asn1:"-" json:"-"`
	ExtCount_                   int64                   `asn1:"-" json:"-"`
	ExtPresent_                 []bool                  `asn1:"-" json:"-"`
	ExtData_                    [][]byte                `asn1:"-" json:"-"`
}

// SSForwardingFeatureList represents the ASN.1 type SSForwardingFeatureList (SEQUENCE_OF).
type SSForwardingFeatureList = []SSForwardingFeature

// SSForwardingFeature represents the ASN.1 type SSForwardingFeature (SEQUENCE).
type SSForwardingFeature struct {
	BasicService          *CommonDataTypesBasicServiceCode     `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus              *SSSSStatus                          `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ForwardedToNumber     *CommonDataTypesISDNAddressString    `asn1:"tag:5,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *CommonDataTypesISDNSubaddressString `asn1:"tag:8,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	ForwardingOptions     *SSForwardingOptions                 `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	NoReplyConditionTime  *SSNoReplyConditionTime              `asn1:"tag:7,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	LongForwardedToNumber *CommonDataTypesFTNAddressString     `asn1:"tag:9,context,implicit,optional" json:"LongForwardedToNumber,omitempty"`
	ExtCount_             int64                                `asn1:"-" json:"-"`
	ExtPresent_           []bool                               `asn1:"-" json:"-"`
	ExtData_              [][]byte                             `asn1:"-" json:"-"`
}

// SSSSStatus represents the ASN.1 type SSSSStatus (OCTET_STRING).
type SSSSStatus = []byte

// SSForwardingOptions represents the ASN.1 type SSForwardingOptions (OCTET_STRING).
type SSForwardingOptions = []byte

// SSCallBarringInfo represents the ASN.1 type SSCallBarringInfo (SEQUENCE).
type SSCallBarringInfo struct {
	SsCode                       *SSSSCode                `asn1:",optional" json:"SsCode,omitempty"`
	CallBarringFeatureList       SSCallBarringFeatureList `asn1:""`
	CallBarringFeatureListIndef_ bool                     `asn1:"-" json:"-"`
	ExtCount_                    int64                    `asn1:"-" json:"-"`
	ExtPresent_                  []bool                   `asn1:"-" json:"-"`
	ExtData_                     [][]byte                 `asn1:"-" json:"-"`
}

// SSCallBarringFeatureList represents the ASN.1 type SSCallBarringFeatureList (SEQUENCE_OF).
type SSCallBarringFeatureList = []SSCallBarringFeature

// SSCallBarringFeature represents the ASN.1 type SSCallBarringFeature (SEQUENCE).
type SSCallBarringFeature struct {
	BasicService *CommonDataTypesBasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSSSStatus                      `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64                            `asn1:"-" json:"-"`
	ExtPresent_  []bool                           `asn1:"-" json:"-"`
	ExtData_     [][]byte                         `asn1:"-" json:"-"`
}

// SSSSData represents the ASN.1 type SSSSData (SEQUENCE).
type SSSSData struct {
	SsCode                      *SSSSCode                     `asn1:",optional" json:"SsCode,omitempty"`
	SsStatus                    *SSSSStatus                   `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	SsSubscriptionOption        *SSSSSubscriptionOption       `asn1:",optional" json:"SsSubscriptionOption,omitempty"`
	BasicServiceGroupList       SSBasicServiceGroupList       `asn1:",optional" json:"BasicServiceGroupList,omitempty"`
	BasicServiceGroupListIndef_ bool                          `asn1:"-" json:"-"`
	DefaultPriority             *CommonDataTypesEMLPPPriority `asn1:",optional" json:"DefaultPriority,omitempty"`
	NbrUser                     *CommonDataTypesMCBearers     `asn1:"tag:5,context,implicit,optional" json:"NbrUser,omitempty"`
	ExtCount_                   int64                         `asn1:"-" json:"-"`
	ExtPresent_                 []bool                        `asn1:"-" json:"-"`
	ExtData_                    [][]byte                      `asn1:"-" json:"-"`
}

// SSSSSubscriptionOption choice constants.
const (
	SSSSSubscriptionOptionChoiceCliRestrictionOption = 1
	SSSSSubscriptionOptionChoiceOverrideCategory     = 2
)

// SSSSSubscriptionOption represents the ASN.1 CHOICE type SSSSSubscriptionOption.
type SSSSSubscriptionOption struct {
	Choice               int
	CliRestrictionOption *SSCliRestrictionOption `json:"CliRestrictionOption,omitempty"`
	OverrideCategory     *SSOverrideCategory     `json:"OverrideCategory,omitempty"`
}

// NewSSSSSubscriptionOptionCliRestrictionOption creates a SSSSSubscriptionOption with the cliRestrictionOption alternative.
func NewSSSSSubscriptionOptionCliRestrictionOption(v SSCliRestrictionOption) SSSSSubscriptionOption {
	return SSSSSubscriptionOption{
		Choice:               SSSSSubscriptionOptionChoiceCliRestrictionOption,
		CliRestrictionOption: &v,
	}
}

// NewSSSSSubscriptionOptionOverrideCategory creates a SSSSSubscriptionOption with the overrideCategory alternative.
func NewSSSSSubscriptionOptionOverrideCategory(v SSOverrideCategory) SSSSSubscriptionOption {
	return SSSSSubscriptionOption{
		Choice:           SSSSSubscriptionOptionChoiceOverrideCategory,
		OverrideCategory: &v,
	}
}

// SSCliRestrictionOption represents the ASN.1 ENUMERATED type SSCliRestrictionOption.
type SSCliRestrictionOption int64

const (
	SSCliRestrictionOptionPermanent                  SSCliRestrictionOption = 0
	SSCliRestrictionOptionTemporaryDefaultRestricted SSCliRestrictionOption = 1
	SSCliRestrictionOptionTemporaryDefaultAllowed    SSCliRestrictionOption = 2
)

func (v SSCliRestrictionOption) String() string {
	switch v {
	case SSCliRestrictionOptionPermanent:
		return "permanent"
	case SSCliRestrictionOptionTemporaryDefaultRestricted:
		return "temporaryDefaultRestricted"
	case SSCliRestrictionOptionTemporaryDefaultAllowed:
		return "temporaryDefaultAllowed"
	default:
		return "unknown"
	}
}

// SSOverrideCategory represents the ASN.1 ENUMERATED type SSOverrideCategory.
type SSOverrideCategory int64

const (
	SSOverrideCategoryOverrideEnabled  SSOverrideCategory = 0
	SSOverrideCategoryOverrideDisabled SSOverrideCategory = 1
)

func (v SSOverrideCategory) String() string {
	switch v {
	case SSOverrideCategoryOverrideEnabled:
		return "overrideEnabled"
	case SSOverrideCategoryOverrideDisabled:
		return "overrideDisabled"
	default:
		return "unknown"
	}
}

// SSSSForBSCode represents the ASN.1 type SSSSForBSCode (SEQUENCE).
type SSSSForBSCode struct {
	SsCode           SSSSCode                         `asn1:""`
	BasicService     *CommonDataTypesBasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	LongFTNSupported *struct{}                        `asn1:"tag:4,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_        int64                            `asn1:"-" json:"-"`
	ExtPresent_      []bool                           `asn1:"-" json:"-"`
	ExtData_         [][]byte                         `asn1:"-" json:"-"`
}

// SSGenericServiceInfo represents the ASN.1 type SSGenericServiceInfo (SEQUENCE).
type SSGenericServiceInfo struct {
	SsStatus                SSSSStatus                    `asn1:""`
	CliRestrictionOption    *SSCliRestrictionOption       `asn1:",optional" json:"CliRestrictionOption,omitempty"`
	MaximumEntitledPriority *CommonDataTypesEMLPPPriority `asn1:"tag:0,context,implicit,optional" json:"MaximumEntitledPriority,omitempty"`
	DefaultPriority         *CommonDataTypesEMLPPPriority `asn1:"tag:1,context,implicit,optional" json:"DefaultPriority,omitempty"`
	CcbsFeatureList         SSCCBSFeatureList             `asn1:"tag:2,context,implicit,optional" json:"CcbsFeatureList,omitempty"`
	CcbsFeatureListIndef_   bool                          `asn1:"-" json:"-"`
	NbrSB                   *CommonDataTypesMaxMCBearers  `asn1:"tag:3,context,implicit,optional" json:"NbrSB,omitempty"`
	NbrUser                 *CommonDataTypesMCBearers     `asn1:"tag:4,context,implicit,optional" json:"NbrUser,omitempty"`
	NbrSN                   *CommonDataTypesMCBearers     `asn1:"tag:5,context,implicit,optional" json:"NbrSN,omitempty"`
	ExtCount_               int64                         `asn1:"-" json:"-"`
	ExtPresent_             []bool                        `asn1:"-" json:"-"`
	ExtData_                [][]byte                      `asn1:"-" json:"-"`
}

// SSCCBSFeatureList represents the ASN.1 type SSCCBSFeatureList (SEQUENCE_OF).
type SSCCBSFeatureList = []SSCCBSFeature

// SSCCBSFeature represents the ASN.1 type SSCCBSFeature (SEQUENCE).
type SSCCBSFeature struct {
	CcbsIndex             *SSCCBSIndex                         `asn1:"tag:0,context,implicit,optional" json:"CcbsIndex,omitempty"`
	BSubscriberNumber     *CommonDataTypesISDNAddressString    `asn1:"tag:1,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	BSubscriberSubaddress *CommonDataTypesISDNSubaddressString `asn1:"tag:2,context,implicit,optional" json:"BSubscriberSubaddress,omitempty"`
	BasicServiceGroup     *CommonDataTypesBasicServiceCode     `asn1:"tag:3,context,explicit,optional" json:"BasicServiceGroup,omitempty"`
	ExtCount_             int64                                `asn1:"-" json:"-"`
	ExtPresent_           []bool                               `asn1:"-" json:"-"`
	ExtData_              [][]byte                             `asn1:"-" json:"-"`
}

// SSCCBSIndex represents the ASN.1 type SSCCBSIndex (INTEGER).
type SSCCBSIndex = int64

// SSInterrogateSSRes choice constants.
const (
	SSInterrogateSSResChoiceSsStatus              = 1
	SSInterrogateSSResChoiceBasicServiceGroupList = 2
	SSInterrogateSSResChoiceForwardingFeatureList = 3
	SSInterrogateSSResChoiceGenericServiceInfo    = 4
)

// SSInterrogateSSRes represents the ASN.1 CHOICE type SSInterrogateSSRes.
type SSInterrogateSSRes struct {
	Choice                int
	SsStatus              *SSSSStatus             `json:"SsStatus,omitempty"`
	BasicServiceGroupList SSBasicServiceGroupList `json:"BasicServiceGroupList,omitempty"`
	ForwardingFeatureList SSForwardingFeatureList `json:"ForwardingFeatureList,omitempty"`
	GenericServiceInfo    *SSGenericServiceInfo   `json:"GenericServiceInfo,omitempty"`
}

// NewSSInterrogateSSResSsStatus creates a SSInterrogateSSRes with the ss-Status alternative.
func NewSSInterrogateSSResSsStatus(v SSSSStatus) SSInterrogateSSRes {
	return SSInterrogateSSRes{
		Choice:   SSInterrogateSSResChoiceSsStatus,
		SsStatus: &v,
	}
}

// NewSSInterrogateSSResBasicServiceGroupList creates a SSInterrogateSSRes with the basicServiceGroupList alternative.
func NewSSInterrogateSSResBasicServiceGroupList(v SSBasicServiceGroupList) SSInterrogateSSRes {
	return SSInterrogateSSRes{
		Choice:                SSInterrogateSSResChoiceBasicServiceGroupList,
		BasicServiceGroupList: v,
	}
}

// NewSSInterrogateSSResForwardingFeatureList creates a SSInterrogateSSRes with the forwardingFeatureList alternative.
func NewSSInterrogateSSResForwardingFeatureList(v SSForwardingFeatureList) SSInterrogateSSRes {
	return SSInterrogateSSRes{
		Choice:                SSInterrogateSSResChoiceForwardingFeatureList,
		ForwardingFeatureList: v,
	}
}

// NewSSInterrogateSSResGenericServiceInfo creates a SSInterrogateSSRes with the genericServiceInfo alternative.
func NewSSInterrogateSSResGenericServiceInfo(v SSGenericServiceInfo) SSInterrogateSSRes {
	return SSInterrogateSSRes{
		Choice:             SSInterrogateSSResChoiceGenericServiceInfo,
		GenericServiceInfo: &v,
	}
}

// SSUSSDArg represents the ASN.1 type SSUSSDArg (SEQUENCE).
type SSUSSDArg struct {
	UssdDataCodingScheme SSUSSDDataCodingScheme            `asn1:""`
	UssdString           SSUSSDString                      `asn1:""`
	AlertingPattern      *CommonDataTypesAlertingPattern   `asn1:",optional" json:"AlertingPattern,omitempty"`
	Msisdn               *CommonDataTypesISDNAddressString `asn1:"tag:0,context,implicit,optional" json:"Msisdn,omitempty"`
	ExtCount_            int64                             `asn1:"-" json:"-"`
	ExtPresent_          []bool                            `asn1:"-" json:"-"`
	ExtData_             [][]byte                          `asn1:"-" json:"-"`
}

// SSUSSDRes represents the ASN.1 type SSUSSDRes (SEQUENCE).
type SSUSSDRes struct {
	UssdDataCodingScheme SSUSSDDataCodingScheme `asn1:""`
	UssdString           SSUSSDString           `asn1:""`
	ExtCount_            int64                  `asn1:"-" json:"-"`
	ExtPresent_          []bool                 `asn1:"-" json:"-"`
	ExtData_             [][]byte               `asn1:"-" json:"-"`
}

// SSUSSDDataCodingScheme represents the ASN.1 type SSUSSDDataCodingScheme (OCTET_STRING).
type SSUSSDDataCodingScheme = []byte

// SSUSSDString represents the ASN.1 type SSUSSDString (OCTET_STRING).
type SSUSSDString = []byte

// SSPassword represents the ASN.1 type SSPassword (NumericString).
type SSPassword = string

// SSGuidanceInfo represents the ASN.1 ENUMERATED type SSGuidanceInfo.
type SSGuidanceInfo int64

const (
	SSGuidanceInfoEnterPW         SSGuidanceInfo = 0
	SSGuidanceInfoEnterNewPW      SSGuidanceInfo = 1
	SSGuidanceInfoEnterNewPWAgain SSGuidanceInfo = 2
)

func (v SSGuidanceInfo) String() string {
	switch v {
	case SSGuidanceInfoEnterPW:
		return "enterPW"
	case SSGuidanceInfoEnterNewPW:
		return "enterNewPW"
	case SSGuidanceInfoEnterNewPWAgain:
		return "enterNewPW-Again"
	default:
		return "unknown"
	}
}

// SSSSList represents the ASN.1 type SSSSList (SEQUENCE_OF).
type SSSSList = []SSSSCode

// SSSSInfoList represents the ASN.1 type SSSSInfoList (SEQUENCE_OF).
type SSSSInfoList = []SSSSInfo

// SSBasicServiceGroupList represents the ASN.1 type SSBasicServiceGroupList (SEQUENCE_OF).
type SSBasicServiceGroupList = []CommonDataTypesBasicServiceCode

// SSSSInvocationNotificationArg represents the ASN.1 type SSSSInvocationNotificationArg (SEQUENCE).
type SSSSInvocationNotificationArg struct {
	Imsi                       CommonDataTypesIMSI                   `asn1:"tag:0,context,implicit"`
	Msisdn                     CommonDataTypesISDNAddressString      `asn1:"tag:1,context,implicit"`
	SsEvent                    SSSSCode                              `asn1:"tag:2,context,implicit"`
	SsEventSpecification       SSSSEventSpecification                `asn1:"tag:3,context,implicit,optional" json:"SsEventSpecification,omitempty"`
	SsEventSpecificationIndef_ bool                                  `asn1:"-" json:"-"`
	ExtensionContainer         *ExtensionDataTypesExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	BSubscriberNumber          *CommonDataTypesISDNAddressString     `asn1:"tag:5,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	CcbsRequestState           *SSCCBSRequestState                   `asn1:"tag:6,context,implicit,optional" json:"CcbsRequestState,omitempty"`
	ExtCount_                  int64                                 `asn1:"-" json:"-"`
	ExtPresent_                []bool                                `asn1:"-" json:"-"`
	ExtData_                   [][]byte                              `asn1:"-" json:"-"`
}

// SSCCBSRequestState represents the ASN.1 ENUMERATED type SSCCBSRequestState.
type SSCCBSRequestState int64

const (
	SSCCBSRequestStateRequest   SSCCBSRequestState = 0
	SSCCBSRequestStateRecall    SSCCBSRequestState = 1
	SSCCBSRequestStateActive    SSCCBSRequestState = 2
	SSCCBSRequestStateCompleted SSCCBSRequestState = 3
	SSCCBSRequestStateSuspended SSCCBSRequestState = 4
	SSCCBSRequestStateFrozen    SSCCBSRequestState = 5
	SSCCBSRequestStateDeleted   SSCCBSRequestState = 6
)

func (v SSCCBSRequestState) String() string {
	switch v {
	case SSCCBSRequestStateRequest:
		return "request"
	case SSCCBSRequestStateRecall:
		return "recall"
	case SSCCBSRequestStateActive:
		return "active"
	case SSCCBSRequestStateCompleted:
		return "completed"
	case SSCCBSRequestStateSuspended:
		return "suspended"
	case SSCCBSRequestStateFrozen:
		return "frozen"
	case SSCCBSRequestStateDeleted:
		return "deleted"
	default:
		return "unknown"
	}
}

// SSSSInvocationNotificationRes represents the ASN.1 type SSSSInvocationNotificationRes (SEQUENCE).
type SSSSInvocationNotificationRes struct {
	ExtensionContainer *ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                 `asn1:"-" json:"-"`
	ExtPresent_        []bool                                `asn1:"-" json:"-"`
	ExtData_           [][]byte                              `asn1:"-" json:"-"`
}

// SSSSEventSpecification represents the ASN.1 type SSSSEventSpecification (SEQUENCE_OF).
type SSSSEventSpecification = []CommonDataTypesAddressString

// SSRegisterCCEntryArg represents the ASN.1 type SSRegisterCCEntryArg (SEQUENCE).
type SSRegisterCCEntryArg struct {
	SsCode      SSSSCode    `asn1:"tag:0,context,implicit"`
	CcbsData    *SSCCBSData `asn1:"tag:1,context,implicit,optional" json:"CcbsData,omitempty"`
	ExtCount_   int64       `asn1:"-" json:"-"`
	ExtPresent_ []bool      `asn1:"-" json:"-"`
	ExtData_    [][]byte    `asn1:"-" json:"-"`
}

// SSCCBSData represents the ASN.1 type SSCCBSData (SEQUENCE).
type SSCCBSData struct {
	CcbsFeature       SSCCBSFeature                     `asn1:"tag:0,context,implicit"`
	TranslatedBNumber CommonDataTypesISDNAddressString  `asn1:"tag:1,context,implicit"`
	ServiceIndicator  *SSServiceIndicator               `asn1:"tag:2,context,implicit,optional" json:"ServiceIndicator,omitempty"`
	CallInfo          CommonDataTypesExternalSignalInfo `asn1:"tag:3,context,implicit"`
	NetworkSignalInfo CommonDataTypesExternalSignalInfo `asn1:"tag:4,context,implicit"`
	ExtCount_         int64                             `asn1:"-" json:"-"`
	ExtPresent_       []bool                            `asn1:"-" json:"-"`
	ExtData_          [][]byte                          `asn1:"-" json:"-"`
}

// SSServiceIndicator represents the ASN.1 type SSServiceIndicator (BIT_STRING).
type SSServiceIndicator = runtime.BitString

// SSRegisterCCEntryRes represents the ASN.1 type SSRegisterCCEntryRes (SEQUENCE).
type SSRegisterCCEntryRes struct {
	CcbsFeature *SSCCBSFeature `asn1:"tag:0,context,implicit,optional" json:"CcbsFeature,omitempty"`
	ExtCount_   int64          `asn1:"-" json:"-"`
	ExtPresent_ []bool         `asn1:"-" json:"-"`
	ExtData_    [][]byte       `asn1:"-" json:"-"`
}

// SSEraseCCEntryArg represents the ASN.1 type SSEraseCCEntryArg (SEQUENCE).
type SSEraseCCEntryArg struct {
	SsCode      SSSSCode     `asn1:"tag:0,context,implicit"`
	CcbsIndex   *SSCCBSIndex `asn1:"tag:1,context,implicit,optional" json:"CcbsIndex,omitempty"`
	ExtCount_   int64        `asn1:"-" json:"-"`
	ExtPresent_ []bool       `asn1:"-" json:"-"`
	ExtData_    [][]byte     `asn1:"-" json:"-"`
}

// SSEraseCCEntryRes represents the ASN.1 type SSEraseCCEntryRes (SEQUENCE).
type SSEraseCCEntryRes struct {
	SsCode      SSSSCode    `asn1:"tag:0,context,implicit"`
	SsStatus    *SSSSStatus `asn1:"tag:1,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_   int64       `asn1:"-" json:"-"`
	ExtPresent_ []bool      `asn1:"-" json:"-"`
	ExtData_    [][]byte    `asn1:"-" json:"-"`
}

// MarshalBER encodes SSRegisterSSArg to BER format.
func (v *SSRegisterSSArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSRegisterSSArg to DER format.
func (v *SSRegisterSSArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSRegisterSSArg from BER/DER format.
func (v *SSRegisterSSArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSRegisterSSArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSRegisterSSArg", Cause: ber.ErrExtraData}
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
	v.SsCode = SSSSCode(val_sscode)
	offset += n
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (CommonDataTypesBasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice CommonDataTypesBasicServiceCode
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
				tmp_forwardedtonumber := CommonDataTypesAddressString(rawVal_forwardedtonumber)
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
				tmp_forwardedtosubaddress := CommonDataTypesISDNSubaddressString(rawVal_forwardedtosubaddress)
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
				tmp_noreplyconditiontime := SSNoReplyConditionTime(decVal_noreplyconditiontime)
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
				tmp_defaultpriority := CommonDataTypesEMLPPPriority(decVal_defaultpriority)
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
				tmp_nbruser := CommonDataTypesMCBearers(decVal_nbruser)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSRegisterSSArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSSSInfo to BER format.
func (v *SSSSInfo) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SSSSInfoChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("choice SSSSInfo: forwardingInfo is nil")
		}
		enc_0, err := v.ForwardingInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingInfo: %w", err)
		}
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_0)
		return enc_0, nil
	case SSSSInfoChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("choice SSSSInfo: callBarringInfo is nil")
		}
		enc_1, err := v.CallBarringInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding callBarringInfo: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_1)
		return enc_1, nil
	case SSSSInfoChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("choice SSSSInfo: ss-Data is nil")
		}
		enc_2, err := v.SsData.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding ss-Data: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSSSInfo", v.Choice)
	}
}

// MarshalDER encodes SSSSInfo to DER format.
func (v *SSSSInfo) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case SSSSInfoChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("choice SSSSInfo: forwardingInfo is nil")
		}
		enc_der_0, err := v.ForwardingInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingInfo: %w", err)
		}
		enc_der_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, true, enc_der_0)
		return enc_der_0, nil
	case SSSSInfoChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("choice SSSSInfo: callBarringInfo is nil")
		}
		enc_der_1, err := v.CallBarringInfo.MarshalDER()
		if err != nil {
			return nil, fmt.Errorf("encoding callBarringInfo: %w", err)
		}
		enc_der_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, true, enc_der_1)
		return enc_der_1, nil
	case SSSSInfoChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("choice SSSSInfo: ss-Data is nil")
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

// UnmarshalBER decodes SSSSInfo from BER/DER format.
func (v *SSSSInfo) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSSSInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSSSInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SSSSInfo CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSSInfo", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SSSSInfoChoiceForwardingInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding forwardingInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SSForwardingInfo
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding forwardingInfo: %w", unmErr)
		}
		v.ForwardingInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SSSSInfoChoiceCallBarringInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding callBarringInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SSCallBarringInfo
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding callBarringInfo: %w", unmErr)
		}
		v.CallBarringInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = SSSSInfoChoiceSsData
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ss-Data: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SSSSData
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding ss-Data: %w", unmErr)
		}
		v.SsData = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SSSSInfo CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SSForwardingInfo to BER format.
func (v *SSForwardingInfo) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		children = append(children, enc_sscode...)
	}
	enc_forwardingfeaturelist, err := MarshalBERSSForwardingFeatureList(v.ForwardingFeatureList)
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

// MarshalDER encodes SSForwardingInfo to DER format.
func (v *SSForwardingInfo) MarshalDER() ([]byte, error) {
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

// UnmarshalBER decodes SSForwardingInfo from BER/DER format.
func (v *SSForwardingInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSForwardingInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSForwardingInfo", Cause: ber.ErrExtraData}
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
				tmp_sscode := SSSSCode(val_sscode)
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
	// Decode nested SEQUENCE_OF (SSForwardingFeatureList)
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
	dec_forwardingfeaturelist, unmErr := UnmarshalBERSSForwardingFeatureList(tlv_forwardingfeaturelist)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSForwardingInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSSForwardingFeatureList encodes a SSForwardingFeatureList list to BER.
func MarshalBERSSForwardingFeatureList(list SSForwardingFeatureList) ([]byte, error) {
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

// UnmarshalBERSSForwardingFeatureList decodes a SSForwardingFeatureList list from BER.
func UnmarshalBERSSForwardingFeatureList(data []byte) (SSForwardingFeatureList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSForwardingFeatureList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSForwardingFeatureList", Cause: ber.ErrExtraData}
	}
	var result SSForwardingFeatureList
	offset := 0
	for offset < len(content) {
		var elem SSForwardingFeature
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

// MarshalBER encodes SSForwardingFeature to BER format.
func (v *SSForwardingFeature) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSForwardingFeature to DER format.
func (v *SSForwardingFeature) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSForwardingFeature from BER/DER format.
func (v *SSForwardingFeature) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSForwardingFeature SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSForwardingFeature", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (CommonDataTypesBasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice CommonDataTypesBasicServiceCode
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
				tmp_ssstatus := SSSSStatus(rawVal_ssstatus)
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
				tmp_forwardedtonumber := CommonDataTypesISDNAddressString(rawVal_forwardedtonumber)
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
				tmp_forwardedtosubaddress := CommonDataTypesISDNSubaddressString(rawVal_forwardedtosubaddress)
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
				tmp_forwardingoptions := SSForwardingOptions(rawVal_forwardingoptions)
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
				tmp_noreplyconditiontime := SSNoReplyConditionTime(decVal_noreplyconditiontime)
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
				tmp_longforwardedtonumber := CommonDataTypesFTNAddressString(rawVal_longforwardedtonumber)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSForwardingFeature", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSCallBarringInfo to BER format.
func (v *SSCallBarringInfo) MarshalBER() ([]byte, error) {
	var children []byte
	if v.SsCode != nil {
		enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		children = append(children, enc_sscode...)
	}
	enc_callbarringfeaturelist, err := MarshalBERSSCallBarringFeatureList(v.CallBarringFeatureList)
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

// MarshalDER encodes SSCallBarringInfo to DER format.
func (v *SSCallBarringInfo) MarshalDER() ([]byte, error) {
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

// UnmarshalBER decodes SSCallBarringInfo from BER/DER format.
func (v *SSCallBarringInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSCallBarringInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSCallBarringInfo", Cause: ber.ErrExtraData}
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
				tmp_sscode := SSSSCode(val_sscode)
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
	// Decode nested SEQUENCE_OF (SSCallBarringFeatureList)
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
	dec_callbarringfeaturelist, unmErr := UnmarshalBERSSCallBarringFeatureList(tlv_callbarringfeaturelist)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSCallBarringInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSSCallBarringFeatureList encodes a SSCallBarringFeatureList list to BER.
func MarshalBERSSCallBarringFeatureList(list SSCallBarringFeatureList) ([]byte, error) {
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

// UnmarshalBERSSCallBarringFeatureList decodes a SSCallBarringFeatureList list from BER.
func UnmarshalBERSSCallBarringFeatureList(data []byte) (SSCallBarringFeatureList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSCallBarringFeatureList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSCallBarringFeatureList", Cause: ber.ErrExtraData}
	}
	var result SSCallBarringFeatureList
	offset := 0
	for offset < len(content) {
		var elem SSCallBarringFeature
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

// MarshalBER encodes SSCallBarringFeature to BER format.
func (v *SSCallBarringFeature) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSCallBarringFeature to DER format.
func (v *SSCallBarringFeature) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSCallBarringFeature from BER/DER format.
func (v *SSCallBarringFeature) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSCallBarringFeature SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSCallBarringFeature", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (CommonDataTypesBasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice CommonDataTypesBasicServiceCode
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
				tmp_ssstatus := SSSSStatus(rawVal_ssstatus)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSCallBarringFeature", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSSSData to BER format.
func (v *SSSSData) MarshalBER() ([]byte, error) {
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
		enc_basicservicegrouplist, err := MarshalBERSSBasicServiceGroupList(v.BasicServiceGroupList)
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

// MarshalDER encodes SSSSData to DER format.
func (v *SSSSData) MarshalDER() ([]byte, error) {
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

// UnmarshalBER decodes SSSSData from BER/DER format.
func (v *SSSSData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSSSData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSSData", Cause: ber.ErrExtraData}
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
				tmp_sscode := SSSSCode(val_sscode)
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
				tmp_ssstatus := SSSSStatus(rawVal_ssstatus)
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
				// Decode nested CHOICE (SSSSSubscriptionOption)
				_, n_sssubscriptionoption, _, tlvErr_sssubscriptionoption := ber.DecodeTLV(content[offset:])
				if tlvErr_sssubscriptionoption != nil {
					return fmt.Errorf("decoding ss-SubscriptionOption: %w", tlvErr_sssubscriptionoption)
				}
				var dec_sssubscriptionoption SSSSSubscriptionOption
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
				// Decode nested SEQUENCE_OF (SSBasicServiceGroupList)
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
				dec_basicservicegrouplist, unmErr := UnmarshalBERSSBasicServiceGroupList(tlv_basicservicegrouplist)
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
				tmp_defaultpriority := CommonDataTypesEMLPPPriority(val_defaultpriority)
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
				tmp_nbruser := CommonDataTypesMCBearers(decVal_nbruser)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSSSData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSSSSubscriptionOption to BER format.
func (v *SSSSSubscriptionOption) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SSSSSubscriptionOptionChoiceCliRestrictionOption:
		if v.CliRestrictionOption == nil {
			return nil, fmt.Errorf("choice SSSSSubscriptionOption: cliRestrictionOption is nil")
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, false, enc_0)
		return enc_0, nil
	case SSSSSubscriptionOptionChoiceOverrideCategory:
		if v.OverrideCategory == nil {
			return nil, fmt.Errorf("choice SSSSSubscriptionOption: overrideCategory is nil")
		}
		enc_1 := ber.EncodeEnumerated(int64(*v.OverrideCategory))
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, false, enc_1)
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSSSSubscriptionOption", v.Choice)
	}
}

// MarshalDER encodes SSSSSubscriptionOption to DER format.
func (v *SSSSSubscriptionOption) MarshalDER() ([]byte, error) {
	return v.MarshalBER()
}

// UnmarshalBER decodes SSSSSubscriptionOption from BER/DER format.
func (v *SSSSSubscriptionOption) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSSSSubscriptionOption CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSSSSubscriptionOption: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SSSSSubscriptionOption CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSSSubscriptionOption", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SSSSSubscriptionOptionChoiceCliRestrictionOption
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding cliRestrictionOption: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding cliRestrictionOption: %w", intErr)
		}
		tmp := SSCliRestrictionOption(decVal)
		v.CliRestrictionOption = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SSSSSubscriptionOptionChoiceOverrideCategory
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding overrideCategory: %w", tlvErr)
		}
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return fmt.Errorf("decoding overrideCategory: %w", intErr)
		}
		tmp := SSOverrideCategory(decVal)
		v.OverrideCategory = &tmp
	} else {
		return fmt.Errorf("unknown tag %s for SSSSSubscriptionOption CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SSSSForBSCode to BER format.
func (v *SSSSForBSCode) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSSSForBSCode to DER format.
func (v *SSSSForBSCode) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSSSForBSCode from BER/DER format.
func (v *SSSSForBSCode) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSSSForBSCode SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSSForBSCode", Cause: ber.ErrExtraData}
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
	v.SsCode = SSSSCode(val_sscode)
	offset += n
	// Decode basicService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				// Decode nested CHOICE (CommonDataTypesBasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:])
				if tlvErr_basicservice != nil {
					return fmt.Errorf("decoding basicService: %w", tlvErr_basicservice)
				}
				var dec_basicservice CommonDataTypesBasicServiceCode
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSSSForBSCode", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSGenericServiceInfo to BER format.
func (v *SSGenericServiceInfo) MarshalBER() ([]byte, error) {
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
		enc_ccbsfeaturelist, err := MarshalBERSSCCBSFeatureList(v.CcbsFeatureList)
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

// MarshalDER encodes SSGenericServiceInfo to DER format.
func (v *SSGenericServiceInfo) MarshalDER() ([]byte, error) {
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

// UnmarshalBER decodes SSGenericServiceInfo from BER/DER format.
func (v *SSGenericServiceInfo) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSGenericServiceInfo SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSGenericServiceInfo", Cause: ber.ErrExtraData}
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
	v.SsStatus = SSSSStatus(val_ssstatus)
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
				tmp_clirestrictionoption := SSCliRestrictionOption(val_clirestrictionoption)
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
				tmp_maximumentitledpriority := CommonDataTypesEMLPPPriority(decVal_maximumentitledpriority)
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
				tmp_defaultpriority := CommonDataTypesEMLPPPriority(decVal_defaultpriority)
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
				dec_ccbsfeaturelist, unmErr := UnmarshalBERSSCCBSFeatureList(reconstructed_ccbsfeaturelist)
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
				tmp_nbrsb := CommonDataTypesMaxMCBearers(decVal_nbrsb)
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
				tmp_nbruser := CommonDataTypesMCBearers(decVal_nbruser)
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
				tmp_nbrsn := CommonDataTypesMCBearers(decVal_nbrsn)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSGenericServiceInfo", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSSCCBSFeatureList encodes a SSCCBSFeatureList list to BER.
func MarshalBERSSCCBSFeatureList(list SSCCBSFeatureList) ([]byte, error) {
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

// UnmarshalBERSSCCBSFeatureList decodes a SSCCBSFeatureList list from BER.
func UnmarshalBERSSCCBSFeatureList(data []byte) (SSCCBSFeatureList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSCCBSFeatureList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSCCBSFeatureList", Cause: ber.ErrExtraData}
	}
	var result SSCCBSFeatureList
	offset := 0
	for offset < len(content) {
		var elem SSCCBSFeature
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

// MarshalBER encodes SSCCBSFeature to BER format.
func (v *SSCCBSFeature) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSCCBSFeature to DER format.
func (v *SSCCBSFeature) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSCCBSFeature from BER/DER format.
func (v *SSCCBSFeature) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSCCBSFeature SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSCCBSFeature", Cause: ber.ErrExtraData}
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
				tmp_ccbsindex := SSCCBSIndex(decVal_ccbsindex)
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
				tmp_bsubscribernumber := CommonDataTypesISDNAddressString(rawVal_bsubscribernumber)
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
				tmp_bsubscribersubaddress := CommonDataTypesISDNSubaddressString(rawVal_bsubscribersubaddress)
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
				var dec_basicservicegroup CommonDataTypesBasicServiceCode
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSCCBSFeature", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSInterrogateSSRes to BER format.
func (v *SSInterrogateSSRes) MarshalBER() ([]byte, error) {
	switch v.Choice {
	case SSInterrogateSSResChoiceSsStatus:
		enc_0 := ber.EncodeOctetString([]byte(*v.SsStatus))
		enc_0 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, false, enc_0)
		return enc_0, nil
	case SSInterrogateSSResChoiceBasicServiceGroupList:
		if v.BasicServiceGroupList == nil {
			return nil, fmt.Errorf("choice SSInterrogateSSRes: basicServiceGroupList is nil")
		}
		enc_1, err := MarshalBERSSBasicServiceGroupList(v.BasicServiceGroupList)
		if err != nil {
			return nil, fmt.Errorf("encoding basicServiceGroupList: %w", err)
		}
		enc_1 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, true, enc_1)
		return enc_1, nil
	case SSInterrogateSSResChoiceForwardingFeatureList:
		if v.ForwardingFeatureList == nil {
			return nil, fmt.Errorf("choice SSInterrogateSSRes: forwardingFeatureList is nil")
		}
		enc_2, err := MarshalBERSSForwardingFeatureList(v.ForwardingFeatureList)
		if err != nil {
			return nil, fmt.Errorf("encoding forwardingFeatureList: %w", err)
		}
		enc_2 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, true, enc_2)
		return enc_2, nil
	case SSInterrogateSSResChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("choice SSInterrogateSSRes: genericServiceInfo is nil")
		}
		enc_3, err := v.GenericServiceInfo.MarshalBER()
		if err != nil {
			return nil, fmt.Errorf("encoding genericServiceInfo: %w", err)
		}
		enc_3 = ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, true, enc_3)
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSInterrogateSSRes", v.Choice)
	}
}

// MarshalDER encodes SSInterrogateSSRes to DER format.
func (v *SSInterrogateSSRes) MarshalDER() ([]byte, error) {
	switch v.Choice {
	case SSInterrogateSSResChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("choice SSInterrogateSSRes: genericServiceInfo is nil")
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

// UnmarshalBER decodes SSInterrogateSSRes from BER/DER format.
func (v *SSInterrogateSSRes) UnmarshalBER(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSInterrogateSSRes CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSInterrogateSSRes: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData)
	if tlvErr != nil {
		return fmt.Errorf("decoding SSInterrogateSSRes CHOICE: %w", tlvErr)
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInterrogateSSRes", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SSInterrogateSSResChoiceSsStatus
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding ss-Status: %w", tlvErr)
		}
		tmp := SSSSStatus(rawVal)
		v.SsStatus = &tmp
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SSInterrogateSSResChoiceBasicServiceGroupList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding basicServiceGroupList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERSSBasicServiceGroupList(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding basicServiceGroupList: %w", unmErr)
		}
		v.BasicServiceGroupList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
		v.Choice = SSInterrogateSSResChoiceForwardingFeatureList
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding forwardingFeatureList: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		dec, unmErr := UnmarshalBERSSForwardingFeatureList(reconstructed)
		if unmErr != nil {
			return fmt.Errorf("decoding forwardingFeatureList: %w", unmErr)
		}
		v.ForwardingFeatureList = dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SSInterrogateSSResChoiceGenericServiceInfo
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData)
		if tlvErr != nil {
			return fmt.Errorf("decoding genericServiceInfo: %w", tlvErr)
		}
		reconstructed := ber.EncodeSequence(rawVal)
		var dec SSGenericServiceInfo
		if unmErr := dec.UnmarshalBER(reconstructed); unmErr != nil {
			return fmt.Errorf("decoding genericServiceInfo: %w", unmErr)
		}
		v.GenericServiceInfo = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SSInterrogateSSRes CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SSUSSDArg to BER format.
func (v *SSUSSDArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSUSSDArg to DER format.
func (v *SSUSSDArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSUSSDArg from BER/DER format.
func (v *SSUSSDArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSUSSDArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSUSSDArg", Cause: ber.ErrExtraData}
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
	v.UssdDataCodingScheme = SSUSSDDataCodingScheme(val_ussddatacodingscheme)
	offset += n
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	val_ussdstring, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ussd-String: %w", err)
	}
	v.UssdString = SSUSSDString(val_ussdstring)
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
				tmp_alertingpattern := CommonDataTypesAlertingPattern(val_alertingpattern)
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
				tmp_msisdn := CommonDataTypesISDNAddressString(rawVal_msisdn)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSUSSDArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSUSSDRes to BER format.
func (v *SSUSSDRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSUSSDRes to DER format.
func (v *SSUSSDRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSUSSDRes from BER/DER format.
func (v *SSUSSDRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSUSSDRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSUSSDRes", Cause: ber.ErrExtraData}
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
	v.UssdDataCodingScheme = SSUSSDDataCodingScheme(val_ussddatacodingscheme)
	offset += n
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	val_ussdstring, n, err := ber.DecodeOctetString(content[offset:])
	if err != nil {
		return fmt.Errorf("decoding ussd-String: %w", err)
	}
	v.UssdString = SSUSSDString(val_ussdstring)
	offset += n
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:])
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSUSSDRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSSSSList encodes a SSSSList list to BER.
func MarshalBERSSSSList(list SSSSList) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSSSSList decodes a SSSSList list from BER.
func UnmarshalBERSSSSList(data []byte) (SSSSList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSSSList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSSSList", Cause: ber.ErrExtraData}
	}
	var result SSSSList
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, SSSSCode(val))
		offset += n
	}
	return result, nil
}

// MarshalBERSSSSInfoList encodes a SSSSInfoList list to BER.
func MarshalBERSSSSInfoList(list SSSSInfoList) ([]byte, error) {
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

// UnmarshalBERSSSSInfoList decodes a SSSSInfoList list from BER.
func UnmarshalBERSSSSInfoList(data []byte) (SSSSInfoList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSSSInfoList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSSSInfoList", Cause: ber.ErrExtraData}
	}
	var result SSSSInfoList
	offset := 0
	for offset < len(content) {
		var elem SSSSInfo
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

// MarshalBERSSBasicServiceGroupList encodes a SSBasicServiceGroupList list to BER.
func MarshalBERSSBasicServiceGroupList(list SSBasicServiceGroupList) ([]byte, error) {
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

// UnmarshalBERSSBasicServiceGroupList decodes a SSBasicServiceGroupList list from BER.
func UnmarshalBERSSBasicServiceGroupList(data []byte) (SSBasicServiceGroupList, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSBasicServiceGroupList: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSBasicServiceGroupList", Cause: ber.ErrExtraData}
	}
	var result SSBasicServiceGroupList
	offset := 0
	for offset < len(content) {
		var elem CommonDataTypesBasicServiceCode
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

// MarshalBER encodes SSSSInvocationNotificationArg to BER format.
func (v *SSSSInvocationNotificationArg) MarshalBER() ([]byte, error) {
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
		enc_sseventspecification, err := MarshalBERSSSSEventSpecification(v.SsEventSpecification)
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

// MarshalDER encodes SSSSInvocationNotificationArg to DER format.
func (v *SSSSInvocationNotificationArg) MarshalDER() ([]byte, error) {
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

// UnmarshalBER decodes SSSSInvocationNotificationArg from BER/DER format.
func (v *SSSSInvocationNotificationArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSSSInvocationNotificationArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSSInvocationNotificationArg", Cause: ber.ErrExtraData}
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
	v.Imsi = CommonDataTypesIMSI(rawVal_imsi)
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
	v.Msisdn = CommonDataTypesISDNAddressString(rawVal_msisdn)
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
	v.SsEvent = SSSSCode(rawVal_ssevent)
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
				dec_sseventspecification, unmErr := UnmarshalBERSSSSEventSpecification(reconstructed_sseventspecification)
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
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
				tmp_bsubscribernumber := CommonDataTypesISDNAddressString(rawVal_bsubscribernumber)
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
				tmp_ccbsrequeststate := SSCCBSRequestState(decVal_ccbsrequeststate)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSSSInvocationNotificationArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSSSInvocationNotificationRes to BER format.
func (v *SSSSInvocationNotificationRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSSSInvocationNotificationRes to DER format.
func (v *SSSSInvocationNotificationRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSSSInvocationNotificationRes from BER/DER format.
func (v *SSSSInvocationNotificationRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSSSInvocationNotificationRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSSInvocationNotificationRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode extensionContainer
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				// Decode nested SEQUENCE (ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:])
				if tlvErr_extensioncontainer != nil {
					return fmt.Errorf("decoding extensionContainer: %w", tlvErr_extensioncontainer)
				}
				var dec_extensioncontainer ExtensionDataTypesExtensionContainer
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSSSInvocationNotificationRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBERSSSSEventSpecification encodes a SSSSEventSpecification list to BER.
func MarshalBERSSSSEventSpecification(list SSSSEventSpecification) ([]byte, error) {
	var children []byte
	for _, elem := range list {
		children = append(children, ber.EncodeOctetString([]byte(elem))...)
	}
	return ber.EncodeSequence(children), nil
}

// UnmarshalBERSSSSEventSpecification decodes a SSSSEventSpecification list from BER.
func UnmarshalBERSSSSEventSpecification(data []byte) (SSSSEventSpecification, error) {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return nil, fmt.Errorf("decoding SSSSEventSpecification: %w", err)
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSSSEventSpecification", Cause: ber.ErrExtraData}
	}
	var result SSSSEventSpecification
	offset := 0
	for offset < len(content) {
		val, n, osErr := ber.DecodeOctetString(content[offset:])
		if osErr != nil {
			return nil, fmt.Errorf("decoding element: %w", osErr)
		}
		result = append(result, CommonDataTypesAddressString(val))
		offset += n
	}
	return result, nil
}

// MarshalBER encodes SSRegisterCCEntryArg to BER format.
func (v *SSRegisterCCEntryArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSRegisterCCEntryArg to DER format.
func (v *SSRegisterCCEntryArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSRegisterCCEntryArg from BER/DER format.
func (v *SSRegisterCCEntryArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSRegisterCCEntryArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSRegisterCCEntryArg", Cause: ber.ErrExtraData}
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
	v.SsCode = SSSSCode(rawVal_sscode)
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
				var dec_ccbsdata SSCCBSData
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSRegisterCCEntryArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSCCBSData to BER format.
func (v *SSCCBSData) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSCCBSData to DER format.
func (v *SSCCBSData) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSCCBSData from BER/DER format.
func (v *SSCCBSData) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSCCBSData SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSCCBSData", Cause: ber.ErrExtraData}
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
	v.TranslatedBNumber = CommonDataTypesISDNAddressString(rawVal_translatedbnumber)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSCCBSData", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSRegisterCCEntryRes to BER format.
func (v *SSRegisterCCEntryRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSRegisterCCEntryRes to DER format.
func (v *SSRegisterCCEntryRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSRegisterCCEntryRes from BER/DER format.
func (v *SSRegisterCCEntryRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSRegisterCCEntryRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSRegisterCCEntryRes", Cause: ber.ErrExtraData}
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
				var dec_ccbsfeature SSCCBSFeature
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSRegisterCCEntryRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSEraseCCEntryArg to BER format.
func (v *SSEraseCCEntryArg) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSEraseCCEntryArg to DER format.
func (v *SSEraseCCEntryArg) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSEraseCCEntryArg from BER/DER format.
func (v *SSEraseCCEntryArg) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSEraseCCEntryArg SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSEraseCCEntryArg", Cause: ber.ErrExtraData}
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
	v.SsCode = SSSSCode(rawVal_sscode)
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
				tmp_ccbsindex := SSCCBSIndex(decVal_ccbsindex)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSEraseCCEntryArg", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}

// MarshalBER encodes SSEraseCCEntryRes to BER format.
func (v *SSEraseCCEntryRes) MarshalBER() ([]byte, error) {
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

// MarshalDER encodes SSEraseCCEntryRes to DER format.
func (v *SSEraseCCEntryRes) MarshalDER() ([]byte, error) {
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDERElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
	}
	// DER is a subset of BER; our BER encoder already uses DER-compatible encoding.
	return v.MarshalBER()
}

// UnmarshalBER decodes SSEraseCCEntryRes from BER/DER format.
func (v *SSEraseCCEntryRes) UnmarshalBER(data []byte) error {
	content, total, err := ber.DecodeSequenceContent(data)
	if err != nil {
		return fmt.Errorf("decoding SSEraseCCEntryRes SEQUENCE: %w", err)
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSEraseCCEntryRes", Cause: ber.ErrExtraData}
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
	v.SsCode = SSSSCode(rawVal_sscode)
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
				tmp_ssstatus := SSSSStatus(rawVal_ssstatus)
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSEraseCCEntryRes", Cause: extErr_}
		}
		v.ExtData_ = append(v.ExtData_, append([]byte(nil), content[offset:offset+nExt_]...))
		v.ExtPresent_ = append(v.ExtPresent_, true)
		offset += nExt_
	}
	v.ExtCount_ = int64(len(v.ExtData_))
	return nil
}
