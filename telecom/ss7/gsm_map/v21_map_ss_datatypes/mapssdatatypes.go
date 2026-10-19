// Code generated from ASN.1 module "MAP-SS-DataTypes". DO NOT EDIT.

package v21_map_ss_datatypes

import (
	"fmt"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/tag"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_commondatatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_extensiondatatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_code"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = ber.EncodeTLV
	_ = tag.ClassUniversal
)

const (

	// SSMaxNumOfCCBSRequests is the integer constant for maxNumOfCCBS-Requests.
	SSMaxNumOfCCBSRequests int64 = 5

	// SSMaxUSSDStringLength is the integer constant for maxUSSD-StringLength.
	SSMaxUSSDStringLength int64 = 160

	// SSMaxNumOfSS is the integer constant for maxNumOfSS.
	SSMaxNumOfSS int64 = 30

	// SSMaxNumOfBasicServiceGroups is the integer constant for maxNumOfBasicServiceGroups.
	SSMaxNumOfBasicServiceGroups int64 = 13

	// SSMaxEventSpecification is the integer constant for maxEventSpecification.
	SSMaxEventSpecification int64 = 2
)

// SSRegisterSSArg represents the ASN.1 type RegisterSS-Arg (SEQUENCE).
type SSRegisterSSArg struct {
	SsCode                v21_map_ss_code.SSSSCode                                     `asn1:""`
	BasicService          *v21_map_commondatatypes.CommonDataTypesBasicServiceCode     `asn1:",optional" json:"BasicService,omitempty"`
	ForwardedToNumber     *v21_map_commondatatypes.CommonDataTypesAddressString        `asn1:"tag:4,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *v21_map_commondatatypes.CommonDataTypesISDNSubaddressString `asn1:"tag:6,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	NoReplyConditionTime  *SSNoReplyConditionTime                                      `asn1:"tag:5,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	DefaultPriority       *v21_map_commondatatypes.CommonDataTypesEMLPPPriority        `asn1:"tag:7,context,implicit,optional" json:"DefaultPriority,omitempty"`
	NbrUser               *v21_map_commondatatypes.CommonDataTypesMCBearers            `asn1:"tag:8,context,implicit,optional" json:"NbrUser,omitempty"`
	LongFTNSupported      *struct{}                                                    `asn1:"tag:9,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_             int64                                                        `asn1:"-" json:"-"`
	ExtPresent_           []bool                                                       `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSNoReplyConditionTime represents the ASN.1 type NoReplyConditionTime (INTEGER).
type SSNoReplyConditionTime = int64

// SSSSInfo choice constants.
const (
	SSSSInfoChoiceForwardingInfo  = 1
	SSSSInfoChoiceCallBarringInfo = 2
	SSSSInfoChoiceSsData          = 3
)

// SSSSInfo represents the ASN.1 CHOICE type SS-Info.
type SSSSInfo struct {
	Choice          int
	berReplayNode_  *ber.ReplayNode    `json:"-"`
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

// SSForwardingInfo represents the ASN.1 type ForwardingInfo (SEQUENCE).
type SSForwardingInfo struct {
	SsCode                         *v21_map_ss_code.SSSSCode `asn1:",optional" json:"SsCode,omitempty"`
	ForwardingFeatureList          *SSForwardingFeatureList  `asn1:""`
	berForwardingFeatureListIndef_ bool                      `asn1:"-" json:"-"`
	ExtCount_                      int64                     `asn1:"-" json:"-"`
	ExtPresent_                    []bool                    `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSForwardingFeatureList represents the ASN.1 type ForwardingFeatureList (SEQUENCE_OF).
type SSForwardingFeatureList struct {
	Values         []SSForwardingFeature `json:"Values"`
	berReplayNode_ *ber.ReplayNode       `json:"-"`
}

// SSForwardingFeature represents the ASN.1 type ForwardingFeature (SEQUENCE).
type SSForwardingFeature struct {
	BasicService          *v21_map_commondatatypes.CommonDataTypesBasicServiceCode     `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus              *SSSSStatus                                                  `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ForwardedToNumber     *v21_map_commondatatypes.CommonDataTypesISDNAddressString    `asn1:"tag:5,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardedToSubaddress *v21_map_commondatatypes.CommonDataTypesISDNSubaddressString `asn1:"tag:8,context,implicit,optional" json:"ForwardedToSubaddress,omitempty"`
	ForwardingOptions     *SSForwardingOptions                                         `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	NoReplyConditionTime  *SSNoReplyConditionTime                                      `asn1:"tag:7,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	LongForwardedToNumber *v21_map_commondatatypes.CommonDataTypesFTNAddressString     `asn1:"tag:9,context,implicit,optional" json:"LongForwardedToNumber,omitempty"`
	ExtCount_             int64                                                        `asn1:"-" json:"-"`
	ExtPresent_           []bool                                                       `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSSSStatus represents the ASN.1 type SS-Status (OCTET_STRING).
type SSSSStatus = []byte

// SSForwardingOptions represents the ASN.1 type ForwardingOptions (OCTET_STRING).
type SSForwardingOptions = []byte

// SSCallBarringInfo represents the ASN.1 type CallBarringInfo (SEQUENCE).
type SSCallBarringInfo struct {
	SsCode                          *v21_map_ss_code.SSSSCode `asn1:",optional" json:"SsCode,omitempty"`
	CallBarringFeatureList          *SSCallBarringFeatureList `asn1:""`
	berCallBarringFeatureListIndef_ bool                      `asn1:"-" json:"-"`
	ExtCount_                       int64                     `asn1:"-" json:"-"`
	ExtPresent_                     []bool                    `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSCallBarringFeatureList represents the ASN.1 type CallBarringFeatureList (SEQUENCE_OF).
type SSCallBarringFeatureList struct {
	Values         []SSCallBarringFeature `json:"Values"`
	berReplayNode_ *ber.ReplayNode        `json:"-"`
}

// SSCallBarringFeature represents the ASN.1 type CallBarringFeature (SEQUENCE).
type SSCallBarringFeature struct {
	BasicService *v21_map_commondatatypes.CommonDataTypesBasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus     *SSSSStatus                                              `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_    int64                                                    `asn1:"-" json:"-"`
	ExtPresent_  []bool                                                   `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSSSData represents the ASN.1 type SS-Data (SEQUENCE).
type SSSSData struct {
	SsCode                         *v21_map_ss_code.SSSSCode                             `asn1:",optional" json:"SsCode,omitempty"`
	SsStatus                       *SSSSStatus                                           `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	SsSubscriptionOption           *SSSSSubscriptionOption                               `asn1:",optional" json:"SsSubscriptionOption,omitempty"`
	BasicServiceGroupList          *SSBasicServiceGroupList                              `asn1:",optional" json:"BasicServiceGroupList,omitempty"`
	berBasicServiceGroupListIndef_ bool                                                  `asn1:"-" json:"-"`
	DefaultPriority                *v21_map_commondatatypes.CommonDataTypesEMLPPPriority `asn1:",optional" json:"DefaultPriority,omitempty"`
	NbrUser                        *v21_map_commondatatypes.CommonDataTypesMCBearers     `asn1:"tag:5,context,implicit,optional" json:"NbrUser,omitempty"`
	ExtCount_                      int64                                                 `asn1:"-" json:"-"`
	ExtPresent_                    []bool                                                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSSSSubscriptionOption choice constants.
const (
	SSSSSubscriptionOptionChoiceCliRestrictionOption = 1
	SSSSSubscriptionOptionChoiceOverrideCategory     = 2
)

// SSSSSubscriptionOption represents the ASN.1 CHOICE type SS-SubscriptionOption.
type SSSSSubscriptionOption struct {
	Choice               int
	berReplayNode_       *ber.ReplayNode         `json:"-"`
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

// SSCliRestrictionOption represents the ASN.1 ENUMERATED type CliRestrictionOption.
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

// SSOverrideCategory represents the ASN.1 ENUMERATED type OverrideCategory.
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

// SSSSForBSCode represents the ASN.1 type SS-ForBS-Code (SEQUENCE).
type SSSSForBSCode struct {
	SsCode           v21_map_ss_code.SSSSCode                                 `asn1:""`
	BasicService     *v21_map_commondatatypes.CommonDataTypesBasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	LongFTNSupported *struct{}                                                `asn1:"tag:4,context,implicit,optional" json:"LongFTNSupported,omitempty"`
	ExtCount_        int64                                                    `asn1:"-" json:"-"`
	ExtPresent_      []bool                                                   `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSGenericServiceInfo represents the ASN.1 type GenericServiceInfo (SEQUENCE).
type SSGenericServiceInfo struct {
	SsStatus                 SSSSStatus                                            `asn1:""`
	CliRestrictionOption     *SSCliRestrictionOption                               `asn1:",optional" json:"CliRestrictionOption,omitempty"`
	MaximumEntitledPriority  *v21_map_commondatatypes.CommonDataTypesEMLPPPriority `asn1:"tag:0,context,implicit,optional" json:"MaximumEntitledPriority,omitempty"`
	DefaultPriority          *v21_map_commondatatypes.CommonDataTypesEMLPPPriority `asn1:"tag:1,context,implicit,optional" json:"DefaultPriority,omitempty"`
	CcbsFeatureList          *SSCCBSFeatureList                                    `asn1:"tag:2,context,implicit,optional" json:"CcbsFeatureList,omitempty"`
	berCcbsFeatureListIndef_ bool                                                  `asn1:"-" json:"-"`
	NbrSB                    *v21_map_commondatatypes.CommonDataTypesMaxMCBearers  `asn1:"tag:3,context,implicit,optional" json:"NbrSB,omitempty"`
	NbrUser                  *v21_map_commondatatypes.CommonDataTypesMCBearers     `asn1:"tag:4,context,implicit,optional" json:"NbrUser,omitempty"`
	NbrSN                    *v21_map_commondatatypes.CommonDataTypesMCBearers     `asn1:"tag:5,context,implicit,optional" json:"NbrSN,omitempty"`
	ExtCount_                int64                                                 `asn1:"-" json:"-"`
	ExtPresent_              []bool                                                `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSCCBSFeatureList represents the ASN.1 type CCBS-FeatureList (SEQUENCE_OF).
type SSCCBSFeatureList struct {
	Values         []SSCCBSFeature `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// SSCCBSFeature represents the ASN.1 type CCBS-Feature (SEQUENCE).
type SSCCBSFeature struct {
	CcbsIndex             *SSCCBSIndex                                                 `asn1:"tag:0,context,implicit,optional" json:"CcbsIndex,omitempty"`
	BSubscriberNumber     *v21_map_commondatatypes.CommonDataTypesISDNAddressString    `asn1:"tag:1,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	BSubscriberSubaddress *v21_map_commondatatypes.CommonDataTypesISDNSubaddressString `asn1:"tag:2,context,implicit,optional" json:"BSubscriberSubaddress,omitempty"`
	BasicServiceGroup     *v21_map_commondatatypes.CommonDataTypesBasicServiceCode     `asn1:"tag:3,context,explicit,optional" json:"BasicServiceGroup,omitempty"`
	ExtCount_             int64                                                        `asn1:"-" json:"-"`
	ExtPresent_           []bool                                                       `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSCCBSIndex represents the ASN.1 type CCBS-Index (INTEGER).
type SSCCBSIndex = int64

// SSInterrogateSSRes choice constants.
const (
	SSInterrogateSSResChoiceSsStatus              = 1
	SSInterrogateSSResChoiceBasicServiceGroupList = 2
	SSInterrogateSSResChoiceForwardingFeatureList = 3
	SSInterrogateSSResChoiceGenericServiceInfo    = 4
)

// SSInterrogateSSRes represents the ASN.1 CHOICE type InterrogateSS-Res.
type SSInterrogateSSRes struct {
	Choice                int
	berReplayNode_        *ber.ReplayNode          `json:"-"`
	SsStatus              *SSSSStatus              `json:"SsStatus,omitempty"`
	BasicServiceGroupList *SSBasicServiceGroupList `json:"BasicServiceGroupList,omitempty"`
	ForwardingFeatureList *SSForwardingFeatureList `json:"ForwardingFeatureList,omitempty"`
	GenericServiceInfo    *SSGenericServiceInfo    `json:"GenericServiceInfo,omitempty"`
}

// NewSSInterrogateSSResSsStatus creates a SSInterrogateSSRes with the ss-Status alternative.
func NewSSInterrogateSSResSsStatus(v SSSSStatus) SSInterrogateSSRes {
	return SSInterrogateSSRes{
		Choice:   SSInterrogateSSResChoiceSsStatus,
		SsStatus: &v,
	}
}

// NewSSInterrogateSSResBasicServiceGroupList creates a SSInterrogateSSRes with the basicServiceGroupList alternative.
func NewSSInterrogateSSResBasicServiceGroupList(v *SSBasicServiceGroupList) SSInterrogateSSRes {
	return SSInterrogateSSRes{
		Choice:                SSInterrogateSSResChoiceBasicServiceGroupList,
		BasicServiceGroupList: v,
	}
}

// NewSSInterrogateSSResForwardingFeatureList creates a SSInterrogateSSRes with the forwardingFeatureList alternative.
func NewSSInterrogateSSResForwardingFeatureList(v *SSForwardingFeatureList) SSInterrogateSSRes {
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

// SSUSSDArg represents the ASN.1 type USSD-Arg (SEQUENCE).
type SSUSSDArg struct {
	UssdDataCodingScheme SSUSSDDataCodingScheme                                    `asn1:""`
	UssdString           SSUSSDString                                              `asn1:""`
	AlertingPattern      *v21_map_commondatatypes.CommonDataTypesAlertingPattern   `asn1:",optional" json:"AlertingPattern,omitempty"`
	Msisdn               *v21_map_commondatatypes.CommonDataTypesISDNAddressString `asn1:"tag:0,context,implicit,optional" json:"Msisdn,omitempty"`
	ExtCount_            int64                                                     `asn1:"-" json:"-"`
	ExtPresent_          []bool                                                    `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSUSSDRes represents the ASN.1 type USSD-Res (SEQUENCE).
type SSUSSDRes struct {
	UssdDataCodingScheme SSUSSDDataCodingScheme `asn1:""`
	UssdString           SSUSSDString           `asn1:""`
	ExtCount_            int64                  `asn1:"-" json:"-"`
	ExtPresent_          []bool                 `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSUSSDDataCodingScheme represents the ASN.1 type USSD-DataCodingScheme (OCTET_STRING).
type SSUSSDDataCodingScheme = []byte

// SSUSSDString represents the ASN.1 type USSD-String (OCTET_STRING).
type SSUSSDString = []byte

// SSPassword represents the ASN.1 type Password (NumericString).
type SSPassword = string

// SSGuidanceInfo represents the ASN.1 ENUMERATED type GuidanceInfo.
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

// SSSSList represents the ASN.1 type SS-List (SEQUENCE_OF).
type SSSSList struct {
	Values         []v21_map_ss_code.SSSSCode `json:"Values"`
	berReplayNode_ *ber.ReplayNode            `json:"-"`
}

// SSSSInfoList represents the ASN.1 type SS-InfoList (SEQUENCE_OF).
type SSSSInfoList struct {
	Values         []SSSSInfo      `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// SSBasicServiceGroupList represents the ASN.1 type BasicServiceGroupList (SEQUENCE_OF).
type SSBasicServiceGroupList struct {
	Values         []v21_map_commondatatypes.CommonDataTypesBasicServiceCode `json:"Values"`
	berReplayNode_ *ber.ReplayNode                                           `json:"-"`
}

// SSSSInvocationNotificationArg represents the ASN.1 type SS-InvocationNotificationArg (SEQUENCE).
type SSSSInvocationNotificationArg struct {
	Imsi                          v21_map_commondatatypes.CommonDataTypesIMSI                      `asn1:"tag:0,context,implicit"`
	Msisdn                        v21_map_commondatatypes.CommonDataTypesISDNAddressString         `asn1:"tag:1,context,implicit"`
	SsEvent                       v21_map_ss_code.SSSSCode                                         `asn1:"tag:2,context,implicit"`
	SsEventSpecification          *SSSSEventSpecification                                          `asn1:"tag:3,context,implicit,optional" json:"SsEventSpecification,omitempty"`
	berSsEventSpecificationIndef_ bool                                                             `asn1:"-" json:"-"`
	ExtensionContainer            *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:"tag:4,context,implicit,optional" json:"ExtensionContainer,omitempty"`
	BSubscriberNumber             *v21_map_commondatatypes.CommonDataTypesISDNAddressString        `asn1:"tag:5,context,implicit,optional" json:"BSubscriberNumber,omitempty"`
	CcbsRequestState              *SSCCBSRequestState                                              `asn1:"tag:6,context,implicit,optional" json:"CcbsRequestState,omitempty"`
	ExtCount_                     int64                                                            `asn1:"-" json:"-"`
	ExtPresent_                   []bool                                                           `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSCCBSRequestState represents the ASN.1 ENUMERATED type CCBS-RequestState.
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

// SSSSInvocationNotificationRes represents the ASN.1 type SS-InvocationNotificationRes (SEQUENCE).
type SSSSInvocationNotificationRes struct {
	ExtensionContainer *v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer `asn1:",optional" json:"ExtensionContainer,omitempty"`
	ExtCount_          int64                                                            `asn1:"-" json:"-"`
	ExtPresent_        []bool                                                           `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSSSEventSpecification represents the ASN.1 type SS-EventSpecification (SEQUENCE_OF).
type SSSSEventSpecification struct {
	Values         []v21_map_commondatatypes.CommonDataTypesAddressString `json:"Values"`
	berReplayNode_ *ber.ReplayNode                                        `json:"-"`
}

// SSRegisterCCEntryArg represents the ASN.1 type RegisterCC-EntryArg (SEQUENCE).
type SSRegisterCCEntryArg struct {
	SsCode      v21_map_ss_code.SSSSCode `asn1:"tag:0,context,implicit"`
	CcbsData    *SSCCBSData              `asn1:"tag:1,context,implicit,optional" json:"CcbsData,omitempty"`
	ExtCount_   int64                    `asn1:"-" json:"-"`
	ExtPresent_ []bool                   `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSCCBSData represents the ASN.1 type CCBS-Data (SEQUENCE).
type SSCCBSData struct {
	CcbsFeature       SSCCBSFeature                                             `asn1:"tag:0,context,implicit"`
	TranslatedBNumber v21_map_commondatatypes.CommonDataTypesISDNAddressString  `asn1:"tag:1,context,implicit"`
	ServiceIndicator  *SSServiceIndicator                                       `asn1:"tag:2,context,implicit,optional" json:"ServiceIndicator,omitempty"`
	CallInfo          v21_map_commondatatypes.CommonDataTypesExternalSignalInfo `asn1:"tag:3,context,implicit"`
	NetworkSignalInfo v21_map_commondatatypes.CommonDataTypesExternalSignalInfo `asn1:"tag:4,context,implicit"`
	ExtCount_         int64                                                     `asn1:"-" json:"-"`
	ExtPresent_       []bool                                                    `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSServiceIndicator represents the ASN.1 type ServiceIndicator (BIT_STRING).
type SSServiceIndicator = runtime.BitString

const (
	// SSServiceIndicatorClirInvoked is position 0 of ASN.1 named bit clir-invoked of ServiceIndicator (ITU-T X.680 (02/2021) §22).
	SSServiceIndicatorClirInvoked = 0
	// SSServiceIndicatorCamelInvoked is position 1 of ASN.1 named bit camel-invoked of ServiceIndicator (ITU-T X.680 (02/2021) §22).
	SSServiceIndicatorCamelInvoked = 1
)

// SSRegisterCCEntryRes represents the ASN.1 type RegisterCC-EntryRes (SEQUENCE).
type SSRegisterCCEntryRes struct {
	CcbsFeature *SSCCBSFeature `asn1:"tag:0,context,implicit,optional" json:"CcbsFeature,omitempty"`
	ExtCount_   int64          `asn1:"-" json:"-"`
	ExtPresent_ []bool         `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSEraseCCEntryArg represents the ASN.1 type EraseCC-EntryArg (SEQUENCE).
type SSEraseCCEntryArg struct {
	SsCode      v21_map_ss_code.SSSSCode `asn1:"tag:0,context,implicit"`
	CcbsIndex   *SSCCBSIndex             `asn1:"tag:1,context,implicit,optional" json:"CcbsIndex,omitempty"`
	ExtCount_   int64                    `asn1:"-" json:"-"`
	ExtPresent_ []bool                   `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSEraseCCEntryRes represents the ASN.1 type EraseCC-EntryRes (SEQUENCE).
type SSEraseCCEntryRes struct {
	SsCode      v21_map_ss_code.SSSSCode `asn1:"tag:0,context,implicit"`
	SsStatus    *SSSSStatus              `asn1:"tag:1,context,implicit,optional" json:"SsStatus,omitempty"`
	ExtCount_   int64                    `asn1:"-" json:"-"`
	ExtPresent_ []bool                   `asn1:"-" json:"-"`
	// ExtData_ retains complete unknown addition TLVs in received order. Fresh
	// BER and DER copy admissible elements without inferring a foreign schema.
	ExtData_       [][]byte        `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// MarshalBER encodes SSRegisterSSArg to BER format.
func (v *SSRegisterSSArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSRegisterSSArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSRegisterSSArg).MarshalBER, (*SSRegisterSSArg).marshalBER, true)

}
func (v *SSRegisterSSArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, s7501b7_0, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, s7501b7_0, "51.5", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, s7501b7_0, "51.5", "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
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
			if constraintErr := checkEncodedValue(opts, s7501b7_0, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := checkEncodedValue(opts, s7501b7_0, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		retagged_enc_defaultpriority, tagErr_enc_defaultpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_defaultpriority)
		if tagErr_enc_defaultpriority != nil {
			return nil, qualifyBERError(tagErr_enc_defaultpriority, "defaultPriority", "encoding", false)
		}
		enc_defaultpriority = retagged_enc_defaultpriority
		children = append(children, enc_defaultpriority...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := checkEncodedValue(opts, s7501b7_0, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, qualifyBERError(tagErr_enc_nbruser, "nbrUser", "encoding", false)
		}
		enc_nbruser = retagged_enc_nbruser
		children = append(children, enc_nbruser...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, qualifyBERError(tagErr_enc_longftnsupported, "longFTN-Supported", "encoding", false)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSRegisterSSArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSRegisterSSArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSRegisterSSArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSRegisterSSArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, s7501b7_0, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(nil, s7501b7_0, "51.5", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(nil, s7501b7_0, "51.5", "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
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
			if constraintErr := checkEncodedValue(nil, s7501b7_0, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := checkEncodedValue(nil, s7501b7_0, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		retagged_enc_defaultpriority, tagErr_enc_defaultpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_defaultpriority)
		if tagErr_enc_defaultpriority != nil {
			return nil, qualifyBERError(tagErr_enc_defaultpriority, "defaultPriority", "encoding", true)
		}
		enc_defaultpriority = retagged_enc_defaultpriority
		children = append(children, enc_defaultpriority...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := checkEncodedValue(nil, s7501b7_0, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, qualifyBERError(tagErr_enc_nbruser, "nbrUser", "encoding", true)
		}
		enc_nbruser = retagged_enc_nbruser
		children = append(children, enc_nbruser...)
	}
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, qualifyBERError(tagErr_enc_longftnsupported, "longFTN-Supported", "encoding", true)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSRegisterSSArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSRegisterSSArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSRegisterSSArg from BER/DER format.
func (destination *SSRegisterSSArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSRegisterSSArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSRegisterSSArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_0, "child", (*SSRegisterSSArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSRegisterSSArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSRegisterSSArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSRegisterSSArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSRegisterSSArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	{
		ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
		val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Code", "decoding", false)
		}
		v.SsCode = v21_map_ss_code.SSSSCode(val_sscode)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
			if constraintErr := checkDecodedLength(opts, s7501b7_0, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
				// Decode nested CHOICE (__asn1pkg_v21_map_commondatatypes.CommonDataTypesBasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return qualifyBERError(tlvErr_basicservice, "basicService", "decoding", false)
				}
				var dec_basicservice v21_map_commondatatypes.CommonDataTypesBasicServiceCode
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicService", "decoding", false)
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
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtonumber), "forwardedToNumber", "decoding", false)
				}
				decVal_forwardedtonumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtonumber.Constructed, rawVal_forwardedtonumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToNumber", "decoding", false)
				}
				tmp_forwardedtonumber := v21_map_commondatatypes.CommonDataTypesAddressString(decVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				if offset < 0 || offset >
					len(content) || n_forwardedtonumber < 0 || n_forwardedtonumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtonumber
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s7501b7_0, "51.5", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtosubaddress), "forwardedToSubaddress", "decoding", false)
				}
				decVal_forwardedtosubaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtosubaddress.Constructed, rawVal_forwardedtosubaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToSubaddress", "decoding", false)
				}
				tmp_forwardedtosubaddress := v21_map_commondatatypes.CommonDataTypesISDNSubaddressString(decVal_forwardedtosubaddress)
				v.ForwardedToSubaddress = &tmp_forwardedtosubaddress
				if offset < 0 || offset >
					len(content) || n_forwardedtosubaddress < 0 || n_forwardedtosubaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtosubaddress
				if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
					if constraintErr := checkDecodedLength(opts, s7501b7_0, "51.5", "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
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
				if decodedTag_noreplyconditiontime.Class != tag.ClassContextSpecific || decodedTag_noreplyconditiontime.Number != 5 || decodedTag_noreplyconditiontime.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_noreplyconditiontime), "noReplyConditionTime", "decoding", false)
				}
				decVal_noreplyconditiontime, intErr := ber.DecodeIntegerValue(rawVal_noreplyconditiontime)
				if intErr != nil {
					return qualifyBERError(intErr, "noReplyConditionTime", "decoding", false)
				}
				tmp_noreplyconditiontime := SSNoReplyConditionTime(decVal_noreplyconditiontime)
				v.NoReplyConditionTime = &tmp_noreplyconditiontime
				if offset < 0 || offset >
					len(content) || n_noreplyconditiontime < 0 || n_noreplyconditiontime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_noreplyconditiontime
				if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
					if constraintErr := checkDecodedValue(opts, s7501b7_0, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "defaultPriority", content[offset:])
				decodedTag_defaultpriority, n_defaultpriority, rawVal_defaultpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "defaultPriority", "decoding", false)
				}
				if decodedTag_defaultpriority.Class != tag.ClassContextSpecific || decodedTag_defaultpriority.Number != 7 || decodedTag_defaultpriority.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_defaultpriority), "defaultPriority", "decoding", false)
				}
				decVal_defaultpriority, intErr := ber.DecodeIntegerValue(rawVal_defaultpriority)
				if intErr != nil {
					return qualifyBERError(intErr, "defaultPriority", "decoding", false)
				}
				tmp_defaultpriority := v21_map_commondatatypes.CommonDataTypesEMLPPPriority(decVal_defaultpriority)
				v.DefaultPriority = &tmp_defaultpriority
				if offset < 0 || offset >
					len(content) || n_defaultpriority < 0 || n_defaultpriority >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_defaultpriority
				if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
					if constraintErr := checkDecodedValue(opts, s7501b7_0, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(*v.DefaultPriority))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "nbrUser", content[offset:])
				decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "nbrUser", "decoding", false)
				}
				if decodedTag_nbruser.Class != tag.ClassContextSpecific || decodedTag_nbruser.Number != 8 || decodedTag_nbruser.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbruser), "nbrUser", "decoding", false)
				}
				decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
				if intErr != nil {
					return qualifyBERError(intErr, "nbrUser", "decoding", false)
				}
				tmp_nbruser := v21_map_commondatatypes.CommonDataTypesMCBearers(decVal_nbruser)
				v.NbrUser = &tmp_nbruser
				if offset < 0 || offset >
					len(content) || n_nbruser < 0 || n_nbruser > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nbruser
				if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
					if constraintErr := checkDecodedValue(opts, s7501b7_0, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(*v.NbrUser))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "longFTN-Supported", content[offset:])
				decodedTag_longftnsupported, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "longFTN-Supported", "decoding", false)
				}
				if decodedTag_longftnsupported.Class != tag.ClassContextSpecific || decodedTag_longftnsupported.Number != 9 || decodedTag_longftnsupported.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longftnsupported), "longFTN-Supported", "decoding", false)
				}
				if len(rawVal_longftnsupported) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_longftnsupported)), "longFTN-Supported", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSRegisterSSArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSRegisterSSArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_0, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes SSSSInfo to BER format.
func (v *SSSSInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSSSInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSSSInfo).MarshalBER, (*SSSSInfo).marshalBER, true)

}
func (v *SSSSInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SSSSInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SSSSInfoChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("%w: choice SSSSInfo: forwardingInfo is nil", ber.ErrInvalidValue)
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
	case SSSSInfoChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("%w: choice SSSSInfo: callBarringInfo is nil", ber.ErrInvalidValue)
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
	case SSSSInfoChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("%w: choice SSSSInfo: ss-Data is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.SsData.MarshalBER(ber.ChildEncodeOptions(opts, "ss-Data")...)
		if err != nil {
			return nil, qualifyBERError(err, "ss-Data", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "ss-Data", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSSSInfo", v.Choice)
	}
}

// MarshalDER encodes SSSSInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSSSInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSSInfo receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SSSSInfoChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("%w: choice SSSSInfo: forwardingInfo is nil", ber.ErrInvalidValue)
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
	case SSSSInfoChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("%w: choice SSSSInfo: callBarringInfo is nil", ber.ErrInvalidValue)
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
	case SSSSInfoChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("%w: choice SSSSInfo: ss-Data is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.SsData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "ss-Data", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "ss-Data", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "ss-Data", "encoding", true)
		}
		return enc_der_2, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SSSSInfoChoiceForwardingInfo:
			return nil, qualifyBERError(err, "forwardingInfo", "encoding", true)
		case SSSSInfoChoiceCallBarringInfo:
			return nil, qualifyBERError(err, "callBarringInfo", "encoding", true)
		case SSSSInfoChoiceSsData:
			return nil, qualifyBERError(err, "ss-Data", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SSSSInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SSSSInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSSSInfo from BER/DER format.
func (destination *SSSSInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSSSInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSSSInfo)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, "MAP-SS-DataTypes.SS-Info", "child", (*SSSSInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSSSInfo).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSSSInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSSSInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSSSInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SSSSInfo CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSSInfo", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSSSInfo.forwardingInfo", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSSSInfo.callBarringInfo", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSSSInfo.ss-Data", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = SSSSInfoChoiceForwardingInfo
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
		var dec SSForwardingInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "forwardingInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "forwardingInfo", "decoding", false)
		}
		v.ForwardingInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = SSSSInfoChoiceCallBarringInfo
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
		var dec SSCallBarringInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "callBarringInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "callBarringInfo", "decoding", false)
		}
		v.CallBarringInfo = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = SSSSInfoChoiceSsData
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
		var dec SSSSData
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "ss-Data")...); unmErr != nil {
			return qualifyBERError(unmErr, "ss-Data", "decoding", false)
		}
		v.SsData = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SSSSInfo CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SSForwardingInfo to BER format.
func (v *SSForwardingInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSForwardingInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSForwardingInfo).MarshalBER, (*SSForwardingInfo).marshalBER, true)

}
func (v *SSForwardingInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := checkEncodedLength(opts, s7501b7_1, "51.5", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(opts, s7501b7_1, "51.5", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_forwardingfeaturelist, err := MarshalBERSSForwardingFeatureList(v.ForwardingFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "forwardingFeatureList"))...)
	if err != nil {
		return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_forwardingfeaturelist)
	children = append(children, enc_forwardingfeaturelist...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
func (v *SSForwardingInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSForwardingInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSForwardingInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSForwardingInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := checkEncodedLength(nil, s7501b7_1, "51.5", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(nil, s7501b7_1, "51.5", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_forwardingfeaturelist, err := MarshalDERSSForwardingFeatureList(v.ForwardingFeatureList)
	if err != nil {
		return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", true)
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
		return nil, fmt.Errorf("%s: %w", "encoding SSForwardingInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSForwardingInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSForwardingInfo from BER/DER format.
func (destination *SSForwardingInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSForwardingInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSForwardingInfo)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_1, "child", (*SSForwardingInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSForwardingInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSForwardingInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSForwardingInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
				val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Code", "decoding", false)
				}
				tmp_sscode := v21_map_ss_code.SSSSCode(val_sscode)
				v.SsCode = &tmp_sscode
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := checkDecodedLength(opts, s7501b7_1, "51.5", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
	{
		v.berForwardingFeatureListIndef_ = false
		ber.MarkPreflightTarget(opts, "forwardingFeatureList", content[offset:])
		// Decode nested SEQUENCE_OF (SSForwardingFeatureList)
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
		dec_forwardingfeaturelist, unmErr := UnmarshalBERSSForwardingFeatureList(tlv_forwardingfeaturelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "forwardingFeatureList"))...)
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
			if constraintErr := checkDecodedLength(opts, s7501b7_1, "51.5", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSForwardingInfo", Cause: extErr_}
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

// MarshalBERSSForwardingFeatureList encodes a SSForwardingFeatureList list to BER.
func MarshalBERSSForwardingFeatureList(collection *SSForwardingFeatureList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSForwardingFeatureList, marshalBERSSForwardingFeatureList, true)

}
func marshalBERSSForwardingFeatureList(collection *SSForwardingFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-SS-DataTypes.marshalBERSSForwardingFeatureList", "51.5", "ForwardingFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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

func appendBERLinearSSForwardingFeatureList(encoder *ber.LinearEncoder, collection *SSForwardingFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSForwardingFeatureList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSForwardingFeatureList encodes a SSForwardingFeatureList list to DER.
func MarshalDERSSForwardingFeatureList(collection *SSForwardingFeatureList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-SS-DataTypes.ForwardingFeatureList", "51.5", "ForwardingFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSForwardingFeatureList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSForwardingFeatureList(encoder *ber.LinearEncoder, collection *SSForwardingFeatureList) ([]byte, error) {
	encoded, err := MarshalDERSSForwardingFeatureList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSForwardingFeatureList decodes a SSForwardingFeatureList list from BER.
func UnmarshalBERSSForwardingFeatureList(data []byte, opts ...ber.DecodeOption) (returnValue *SSForwardingFeatureList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-SS-DataTypes.ForwardingFeatureList", "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERSSForwardingFeatureList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSForwardingFeatureList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSForwardingFeatureList", Cause: ber.ErrExtraData}
	}
	var result []SSForwardingFeature
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem SSForwardingFeature
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
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-SS-DataTypes.ForwardingFeatureList", "51.5", "ForwardingFeatureList", "SIZE (1..13)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSForwardingFeatureList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSForwardingFeatureList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SSForwardingFeature to BER format.
func (v *SSForwardingFeature) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSForwardingFeature receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSForwardingFeature).MarshalBER, (*SSForwardingFeature).marshalBER, true)

}
func (v *SSForwardingFeature) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
			if constraintErr := checkEncodedLength(opts, s7501b7_2, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, s7501b7_2, "51.5", "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s7501b7_2, "51.5", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, s7501b7_2, "51.5", "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, s7501b7_2, "51.5", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
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
			if constraintErr := checkEncodedValue(opts, s7501b7_2, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
	if v.LongForwardedToNumber != nil {
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 15 {
			if constraintErr := checkEncodedLength(opts, s7501b7_2, "51.5", "longForwardedToNumber", "SIZE (1..15)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s7501b7_2, "51.5", "longForwardedToNumber", "SIZE (1..20)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_longforwardedtonumber, encodeErr_enc_longforwardedtonumber := ber.EncodeOctetString([]byte(*v.LongForwardedToNumber))
		if encodeErr_enc_longforwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_longforwardedtonumber, "longForwardedToNumber", "encoding", false)
		}
		retagged_enc_longforwardedtonumber, tagErr_enc_longforwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_longforwardedtonumber)
		if tagErr_enc_longforwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_longforwardedtonumber, "longForwardedToNumber", "encoding", false)
		}
		enc_longforwardedtonumber = retagged_enc_longforwardedtonumber
		children = append(children, enc_longforwardedtonumber...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSForwardingFeature) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSForwardingFeature to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSForwardingFeature) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSForwardingFeature receiver is nil", ber.ErrInvalidValue)
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
			if constraintErr := checkEncodedLength(nil, s7501b7_2, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(nil, s7501b7_2, "51.5", "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s7501b7_2, "51.5", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(nil, s7501b7_2, "51.5", "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(nil, s7501b7_2, "51.5", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
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
			if constraintErr := checkEncodedValue(nil, s7501b7_2, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
	if v.LongForwardedToNumber != nil {
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 15 {
			if constraintErr := checkEncodedLength(nil, s7501b7_2, "51.5", "longForwardedToNumber", "SIZE (1..15)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s7501b7_2, "51.5", "longForwardedToNumber", "SIZE (1..20)", len(*v.LongForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_longforwardedtonumber, encodeErr_enc_longforwardedtonumber := ber.EncodeOctetString([]byte(*v.LongForwardedToNumber))
		if encodeErr_enc_longforwardedtonumber != nil {
			return nil, qualifyBERError(encodeErr_enc_longforwardedtonumber, "longForwardedToNumber", "encoding", true)
		}
		retagged_enc_longforwardedtonumber, tagErr_enc_longforwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_longforwardedtonumber)
		if tagErr_enc_longforwardedtonumber != nil {
			return nil, qualifyBERError(tagErr_enc_longforwardedtonumber, "longForwardedToNumber", "encoding", true)
		}
		enc_longforwardedtonumber = retagged_enc_longforwardedtonumber
		children = append(children, enc_longforwardedtonumber...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSForwardingFeature as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSForwardingFeature) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSForwardingFeature from BER/DER format.
func (destination *SSForwardingFeature) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSForwardingFeature destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSForwardingFeature)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_2, "child", (*SSForwardingFeature).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSForwardingFeature{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSForwardingFeature).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSForwardingFeature SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "basicService", content[offset:])
				// Decode nested CHOICE (__asn1pkg_v21_map_commondatatypes.CommonDataTypesBasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return qualifyBERError(tlvErr_basicservice, "basicService", "decoding", false)
				}
				var dec_basicservice v21_map_commondatatypes.CommonDataTypesBasicServiceCode
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
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus), "ss-Status", "decoding", false)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "ss-Status", "decoding", false)
				}
				tmp_ssstatus := SSSSStatus(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := checkDecodedLength(opts, s7501b7_2, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtonumber), "forwardedToNumber", "decoding", false)
				}
				decVal_forwardedtonumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtonumber.Constructed, rawVal_forwardedtonumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToNumber", "decoding", false)
				}
				tmp_forwardedtonumber := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				if offset < 0 || offset >
					len(content) || n_forwardedtonumber < 0 || n_forwardedtonumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtonumber
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 9 {
					if constraintErr := checkDecodedLength(opts, s7501b7_2, "51.5", "forwardedToNumber", "SIZE (1..9)", len(*v.ForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s7501b7_2, "51.5", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardedtosubaddress), "forwardedToSubaddress", "decoding", false)
				}
				decVal_forwardedtosubaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardedtosubaddress.Constructed, rawVal_forwardedtosubaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardedToSubaddress", "decoding", false)
				}
				tmp_forwardedtosubaddress := v21_map_commondatatypes.CommonDataTypesISDNSubaddressString(decVal_forwardedtosubaddress)
				v.ForwardedToSubaddress = &tmp_forwardedtosubaddress
				if offset < 0 || offset >
					len(content) || n_forwardedtosubaddress < 0 || n_forwardedtosubaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtosubaddress
				if len(*v.ForwardedToSubaddress) < 1 || len(*v.ForwardedToSubaddress) > 21 {
					if constraintErr := checkDecodedLength(opts, s7501b7_2, "51.5", "forwardedToSubaddress", "SIZE (1..21)", len(*v.ForwardedToSubaddress)); constraintErr != nil {
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
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_forwardingoptions), "forwardingOptions", "decoding", false)
				}
				decVal_forwardingoptions, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_forwardingoptions.Constructed, rawVal_forwardingoptions, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "forwardingOptions", "decoding", false)
				}
				tmp_forwardingoptions := SSForwardingOptions(decVal_forwardingoptions)
				v.ForwardingOptions = &tmp_forwardingoptions
				if offset < 0 || offset >
					len(content) || n_forwardingoptions < 0 || n_forwardingoptions >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardingoptions
				if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
					if constraintErr := checkDecodedLength(opts, s7501b7_2, "51.5", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
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
				if decodedTag_noreplyconditiontime.Class != tag.ClassContextSpecific || decodedTag_noreplyconditiontime.Number != 7 || decodedTag_noreplyconditiontime.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_noreplyconditiontime), "noReplyConditionTime", "decoding", false)
				}
				decVal_noreplyconditiontime, intErr := ber.DecodeIntegerValue(rawVal_noreplyconditiontime)
				if intErr != nil {
					return qualifyBERError(intErr, "noReplyConditionTime", "decoding", false)
				}
				tmp_noreplyconditiontime := SSNoReplyConditionTime(decVal_noreplyconditiontime)
				v.NoReplyConditionTime = &tmp_noreplyconditiontime
				if offset < 0 || offset >
					len(content) || n_noreplyconditiontime < 0 || n_noreplyconditiontime >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_noreplyconditiontime
				if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
					if constraintErr := checkDecodedValue(opts, s7501b7_2, "51.4", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "longForwardedToNumber", content[offset:])
				decodedTag_longforwardedtonumber, n_longforwardedtonumber, rawVal_longforwardedtonumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "longForwardedToNumber", "decoding", false)
				}
				if decodedTag_longforwardedtonumber.Class != tag.ClassContextSpecific || decodedTag_longforwardedtonumber.Number != 9 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longforwardedtonumber), "longForwardedToNumber", "decoding", false)
				}
				decVal_longforwardedtonumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_longforwardedtonumber.Constructed, rawVal_longforwardedtonumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "longForwardedToNumber", "decoding", false)
				}
				tmp_longforwardedtonumber := v21_map_commondatatypes.CommonDataTypesFTNAddressString(decVal_longforwardedtonumber)
				v.LongForwardedToNumber = &tmp_longforwardedtonumber
				if offset < 0 || offset >
					len(content) || n_longforwardedtonumber < 0 || n_longforwardedtonumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_longforwardedtonumber
				if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 15 {
					if constraintErr := checkDecodedLength(opts, s7501b7_2, "51.5", "longForwardedToNumber", "SIZE (1..15)", len(*v.LongForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.LongForwardedToNumber) < 1 || len(*v.LongForwardedToNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s7501b7_2, "51.5", "longForwardedToNumber", "SIZE (1..20)", len(*v.LongForwardedToNumber)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSForwardingFeature", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSForwardingFeature", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_2, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBERSSSSStatus encodes a typed standalone SSSSStatus, preserving unchanged received BER.
func MarshalBERSSSSStatus(value *BERValue[SSSSStatus], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required SSSSStatus is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERSSSSStatus, marshalBERSSSSStatus, false)

}
func marshalBERSSSSStatus(value *BERValue[SSSSStatus], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value SSSSStatus }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 1 {
		if constraintErr := checkEncodedLength(opts, "MAP-SS-DataTypes.marshalBERSSSSStatus", "51.5", "SS-Status", "SIZE (1)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SS-Status", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERSSSSStatus encodes a typed standalone SSSSStatus using DER.
func MarshalDERSSSSStatus(value *BERValue[SSSSStatus]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required SSSSStatus is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value SSSSStatus }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 1 {
		if constraintErr := checkEncodedLength(nil, "MAP-SS-DataTypes.SS-Status", "51.5", "SS-Status", "SIZE (1)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SS-Status", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERSSSSStatus decodes one complete typed standalone SSSSStatus from BER/DER.
func UnmarshalBERSSSSStatus(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[SSSSStatus], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-SS-DataTypes.SS-Status", "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERSSSSStatus(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	v := &struct{ Value SSSSStatus }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "SS-Status", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding SS-Status", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = SSSSStatus(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 1 || len(v.Value) > 1 {
			if constraintErr := checkDecodedLength(opts, "MAP-SS-DataTypes.SS-Status", "51.5", "SS-Status", "SIZE (1)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[SSSSStatus]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSSSStatus); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SSCallBarringInfo to BER format.
func (v *SSCallBarringInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSCallBarringInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSCallBarringInfo).MarshalBER, (*SSCallBarringInfo).marshalBER, true)

}
func (v *SSCallBarringInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := checkEncodedLength(opts, s7501b7_3, "51.5", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(opts, s7501b7_3, "51.5", "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callbarringfeaturelist, err := MarshalBERSSCallBarringFeatureList(v.CallBarringFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "callBarringFeatureList"))...)
	if err != nil {
		return nil, qualifyBERError(err, "callBarringFeatureList", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_callbarringfeaturelist)
	children = append(children, enc_callbarringfeaturelist...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
func (v *SSCallBarringInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSCallBarringInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSCallBarringInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSCallBarringInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := checkEncodedLength(nil, s7501b7_3, "51.5", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(nil, s7501b7_3, "51.5", "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callbarringfeaturelist, err := MarshalDERSSCallBarringFeatureList(v.CallBarringFeatureList)
	if err != nil {
		return nil, qualifyBERError(err, "callBarringFeatureList", "encoding", true)
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
		return nil, fmt.Errorf("%s: %w", "encoding SSCallBarringInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSCallBarringInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSCallBarringInfo from BER/DER format.
func (destination *SSCallBarringInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSCallBarringInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSCallBarringInfo)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_3, "child", (*SSCallBarringInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSCallBarringInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSCallBarringInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSCallBarringInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
				val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Code", "decoding", false)
				}
				tmp_sscode := v21_map_ss_code.SSSSCode(val_sscode)
				v.SsCode = &tmp_sscode
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := checkDecodedLength(opts, s7501b7_3, "51.5", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
	{
		v.berCallBarringFeatureListIndef_ = false
		ber.MarkPreflightTarget(opts, "callBarringFeatureList", content[offset:])
		// Decode nested SEQUENCE_OF (SSCallBarringFeatureList)
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
		dec_callbarringfeaturelist, unmErr := UnmarshalBERSSCallBarringFeatureList(tlv_callbarringfeaturelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "callBarringFeatureList"))...)
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
			if constraintErr := checkDecodedLength(opts, s7501b7_3, "51.5", "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSCallBarringInfo", Cause: extErr_}
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

// MarshalBERSSCallBarringFeatureList encodes a SSCallBarringFeatureList list to BER.
func MarshalBERSSCallBarringFeatureList(collection *SSCallBarringFeatureList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSCallBarringFeatureList, marshalBERSSCallBarringFeatureList, true)

}
func marshalBERSSCallBarringFeatureList(collection *SSCallBarringFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-SS-DataTypes.marshalBERSSCallBarringFeatureList", "51.5", "CallBarringFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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

func appendBERLinearSSCallBarringFeatureList(encoder *ber.LinearEncoder, collection *SSCallBarringFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSCallBarringFeatureList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSCallBarringFeatureList encodes a SSCallBarringFeatureList list to DER.
func MarshalDERSSCallBarringFeatureList(collection *SSCallBarringFeatureList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-SS-DataTypes.CallBarringFeatureList", "51.5", "CallBarringFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSCallBarringFeatureList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSCallBarringFeatureList(encoder *ber.LinearEncoder, collection *SSCallBarringFeatureList) ([]byte, error) {
	encoded, err := MarshalDERSSCallBarringFeatureList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSCallBarringFeatureList decodes a SSCallBarringFeatureList list from BER.
func UnmarshalBERSSCallBarringFeatureList(data []byte, opts ...ber.DecodeOption) (returnValue *SSCallBarringFeatureList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-SS-DataTypes.CallBarringFeatureList", "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERSSCallBarringFeatureList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSCallBarringFeatureList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSCallBarringFeatureList", Cause: ber.ErrExtraData}
	}
	var result []SSCallBarringFeature
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem SSCallBarringFeature
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
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-SS-DataTypes.CallBarringFeatureList", "51.5", "CallBarringFeatureList", "SIZE (1..13)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSCallBarringFeatureList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSCallBarringFeatureList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SSCallBarringFeature to BER format.
func (v *SSCallBarringFeature) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSCallBarringFeature receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSCallBarringFeature).MarshalBER, (*SSCallBarringFeature).marshalBER, true)

}
func (v *SSCallBarringFeature) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
			if constraintErr := checkEncodedLength(opts, s7501b7_4, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSCallBarringFeature) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSCallBarringFeature to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSCallBarringFeature) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSCallBarringFeature receiver is nil", ber.ErrInvalidValue)
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
			if constraintErr := checkEncodedLength(nil, s7501b7_4, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSCallBarringFeature as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSCallBarringFeature) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSCallBarringFeature from BER/DER format.
func (destination *SSCallBarringFeature) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSCallBarringFeature destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSCallBarringFeature)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_4, "child", (*SSCallBarringFeature).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSCallBarringFeature{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSCallBarringFeature).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSCallBarringFeature SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "basicService", content[offset:])
				// Decode nested CHOICE (__asn1pkg_v21_map_commondatatypes.CommonDataTypesBasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return qualifyBERError(tlvErr_basicservice, "basicService", "decoding", false)
				}
				var dec_basicservice v21_map_commondatatypes.CommonDataTypesBasicServiceCode
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
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus), "ss-Status", "decoding", false)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "ss-Status", "decoding", false)
				}
				tmp_ssstatus := SSSSStatus(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := checkDecodedLength(opts, s7501b7_4, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSCallBarringFeature", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSCallBarringFeature", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_4, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes SSSSData to BER format.
func (v *SSSSData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSSSData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSSSData).MarshalBER, (*SSSSData).marshalBER, true)

}
func (v *SSSSData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := checkEncodedLength(opts, s7501b7_5, "51.5", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, s7501b7_5, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, s7501b7_5, "51.5", "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservicegrouplist, err := MarshalBERSSBasicServiceGroupList(v.BasicServiceGroupList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "basicServiceGroupList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservicegrouplist)
		children = append(children, enc_basicservicegrouplist...)
	}
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := checkEncodedValue(opts, s7501b7_5, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		children = append(children, enc_defaultpriority...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := checkEncodedValue(opts, s7501b7_5, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, qualifyBERError(tagErr_enc_nbruser, "nbrUser", "encoding", false)
		}
		enc_nbruser = retagged_enc_nbruser
		children = append(children, enc_nbruser...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSSSData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSSSData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSSSData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSSData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := checkEncodedLength(nil, s7501b7_5, "51.5", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(nil, s7501b7_5, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(nil, s7501b7_5, "51.5", "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservicegrouplist, err := MarshalDERSSBasicServiceGroupList(v.BasicServiceGroupList)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", true)
		}
		children = append(children, enc_basicservicegrouplist...)
	}
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := checkEncodedValue(nil, s7501b7_5, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		children = append(children, enc_defaultpriority...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := checkEncodedValue(nil, s7501b7_5, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, qualifyBERError(tagErr_enc_nbruser, "nbrUser", "encoding", true)
		}
		enc_nbruser = retagged_enc_nbruser
		children = append(children, enc_nbruser...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSSSData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSSSData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSSSData from BER/DER format.
func (destination *SSSSData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSSSData destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSSSData)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_5, "child", (*SSSSData).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSSSData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSSSData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSSSData SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
				val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Code", "decoding", false)
				}
				tmp_sscode := v21_map_ss_code.SSSSCode(val_sscode)
				v.SsCode = &tmp_sscode
				if offset > len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := checkDecodedLength(opts, s7501b7_5, "51.5", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus), "ss-Status", "decoding", false)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "ss-Status", "decoding", false)
				}
				tmp_ssstatus := SSSSStatus(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := checkDecodedLength(opts, s7501b7_5, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
				// Decode nested CHOICE (SSSSSubscriptionOption)
				_, n_sssubscriptionoption, _, tlvErr_sssubscriptionoption := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_sssubscriptionoption != nil {
					return qualifyBERError(tlvErr_sssubscriptionoption, "ss-SubscriptionOption", "decoding", false)
				}
				var dec_sssubscriptionoption SSSSSubscriptionOption
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
				// Decode nested SEQUENCE_OF (SSBasicServiceGroupList)
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
				dec_basicservicegrouplist, unmErr := UnmarshalBERSSBasicServiceGroupList(tlv_basicservicegrouplist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "basicServiceGroupList"))...)
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
					if constraintErr := checkDecodedLength(opts, s7501b7_5, "51.5", "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "defaultPriority", content[offset:])
				val_defaultpriority, n, err := ber.DecodeInteger(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "defaultPriority", "decoding", false)
				}
				tmp_defaultpriority := v21_map_commondatatypes.CommonDataTypesEMLPPPriority(val_defaultpriority)
				v.DefaultPriority = &tmp_defaultpriority
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
					if constraintErr := checkDecodedValue(opts, s7501b7_5, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(*v.DefaultPriority))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "nbrUser", content[offset:])
				decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "nbrUser", "decoding", false)
				}
				if decodedTag_nbruser.Class != tag.ClassContextSpecific || decodedTag_nbruser.Number != 5 || decodedTag_nbruser.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbruser), "nbrUser", "decoding", false)
				}
				decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
				if intErr != nil {
					return qualifyBERError(intErr, "nbrUser", "decoding", false)
				}
				tmp_nbruser := v21_map_commondatatypes.CommonDataTypesMCBearers(decVal_nbruser)
				v.NbrUser = &tmp_nbruser
				if offset < 0 || offset >
					len(content) || n_nbruser < 0 || n_nbruser > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nbruser
				if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
					if constraintErr := checkDecodedValue(opts, s7501b7_5, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(*v.NbrUser))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSSSData", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 2) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSSSData", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_5, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes SSSSSubscriptionOption to BER format.
func (v *SSSSSubscriptionOption) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSSSSubscriptionOption receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSSSSubscriptionOption).MarshalBER, (*SSSSSubscriptionOption).marshalBER, true)

}
func (v *SSSSSubscriptionOption) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SSSSSubscriptionOption) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SSSSSubscriptionOptionChoiceCliRestrictionOption:
		if v.CliRestrictionOption == nil {
			return nil, fmt.Errorf("%w: choice SSSSSubscriptionOption: cliRestrictionOption is nil", ber.ErrInvalidValue)
		}
		enc_0 := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
			if constraintErr := checkEncodedValue(opts, s7501b7_6, "20", "cliRestrictionOption", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "cliRestrictionOption", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SSSSSubscriptionOptionChoiceOverrideCategory:
		if v.OverrideCategory == nil {
			return nil, fmt.Errorf("%w: choice SSSSSubscriptionOption: overrideCategory is nil", ber.ErrInvalidValue)
		}
		enc_1 := ber.EncodeEnumerated(int64(*v.OverrideCategory))
		if int64(*v.OverrideCategory) != 0 && int64(*v.OverrideCategory) != 1 {
			if constraintErr := checkEncodedValue(opts, s7501b7_6, "20", "overrideCategory", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.OverrideCategory))); constraintErr != nil {
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
		return nil, fmt.Errorf("unknown choice %d for SSSSSubscriptionOption", v.Choice)
	}
}

// MarshalDER encodes SSSSSubscriptionOption to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSSSSubscriptionOption) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSSSubscriptionOption receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SSSSSubscriptionOptionChoiceCliRestrictionOption:
			return nil, qualifyBERError(err, "cliRestrictionOption", "encoding", true)
		case SSSSSubscriptionOptionChoiceOverrideCategory:
			return nil, qualifyBERError(err, "overrideCategory", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SSSSSubscriptionOption as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SSSSSubscriptionOption) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSSSSubscriptionOption from BER/DER format.
func (destination *SSSSSubscriptionOption) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSSSSubscriptionOption destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSSSSubscriptionOption)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_6, "child", (*SSSSSubscriptionOption).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSSSSubscriptionOption).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSSSSubscriptionOption{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSSSSubscriptionOption CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSSSSubscriptionOption: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SSSSSubscriptionOption CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSSSubscriptionOption", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSSSSubscriptionOption.cliRestrictionOption", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSSSSubscriptionOption.overrideCategory", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == false {
		v.Choice = SSSSSubscriptionOptionChoiceCliRestrictionOption
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
		tmp := SSCliRestrictionOption(decVal)
		v.CliRestrictionOption = &tmp
		if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
			if constraintErr := checkDecodedValue(opts, s7501b7_6, "20", "cliRestrictionOption", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == false {
		v.Choice = SSSSSubscriptionOptionChoiceOverrideCategory
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
		tmp := SSOverrideCategory(decVal)
		v.OverrideCategory = &tmp
		if int64(*v.OverrideCategory) != 0 && int64(*v.OverrideCategory) != 1 {
			if constraintErr := checkDecodedValue(opts, s7501b7_6, "20", "overrideCategory", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.OverrideCategory))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("unknown tag %s for SSSSSubscriptionOption CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SSSSForBSCode to BER format.
func (v *SSSSForBSCode) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSSSForBSCode receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSSSForBSCode).MarshalBER, (*SSSSForBSCode).marshalBER, true)

}
func (v *SSSSForBSCode) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, s7501b7_7, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, qualifyBERError(tagErr_enc_longftnsupported, "longFTN-Supported", "encoding", false)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSSSForBSCode) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSSSForBSCode to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSSSForBSCode) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSSForBSCode receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, s7501b7_7, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	if v.LongFTNSupported != nil {
		enc_longftnsupported := ber.EncodeNull()
		retagged_enc_longftnsupported, tagErr_enc_longftnsupported := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_longftnsupported)
		if tagErr_enc_longftnsupported != nil {
			return nil, qualifyBERError(tagErr_enc_longftnsupported, "longFTN-Supported", "encoding", true)
		}
		enc_longftnsupported = retagged_enc_longftnsupported
		children = append(children, enc_longftnsupported...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSSSForBSCode as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSSSForBSCode) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSSSForBSCode from BER/DER format.
func (destination *SSSSForBSCode) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSSSForBSCode destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSSSForBSCode)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_7, "child", (*SSSSForBSCode).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSSSForBSCode{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSSSForBSCode).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSSSForBSCode SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSSSForBSCode", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Code")
	}
	{
		ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
		val_sscode, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Code", "decoding", false)
		}
		v.SsCode = v21_map_ss_code.SSSSCode(val_sscode)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
			if constraintErr := checkDecodedLength(opts, s7501b7_7, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
				// Decode nested CHOICE (__asn1pkg_v21_map_commondatatypes.CommonDataTypesBasicServiceCode)
				_, n_basicservice, _, tlvErr_basicservice := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservice != nil {
					return qualifyBERError(tlvErr_basicservice, "basicService", "decoding", false)
				}
				var dec_basicservice v21_map_commondatatypes.CommonDataTypesBasicServiceCode
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
	// Decode longFTN-Supported
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "longFTN-Supported", content[offset:])
				decodedTag_longftnsupported, n_longftnsupported, rawVal_longftnsupported, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "longFTN-Supported", "decoding", false)
				}
				if decodedTag_longftnsupported.Class != tag.ClassContextSpecific || decodedTag_longftnsupported.Number != 4 || decodedTag_longftnsupported.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_longftnsupported), "longFTN-Supported", "decoding", false)
				}
				if len(rawVal_longftnsupported) != 0 {
					return qualifyBERError(fmt.Errorf("%w: NULL content length %d", ber.ErrInvalidValue, len(rawVal_longftnsupported)), "longFTN-Supported", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSSSForBSCode", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSSSForBSCode", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_7, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes SSGenericServiceInfo to BER format.
func (v *SSGenericServiceInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSGenericServiceInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSGenericServiceInfo).MarshalBER, (*SSGenericServiceInfo).marshalBER, true)

}
func (v *SSGenericServiceInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := checkEncodedLength(opts, s7501b7_8, "51.5", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
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
			if constraintErr := checkEncodedValue(opts, s7501b7_8, "20", "cliRestrictionOption", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_clirestrictionoption := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		children = append(children, enc_clirestrictionoption...)
	}
	if v.MaximumEntitledPriority != nil {
		if !(int64(*v.MaximumEntitledPriority) >= 0 && int64(*v.MaximumEntitledPriority) <= 15) {
			if constraintErr := checkEncodedValue(opts, s7501b7_8, "51.4", "maximumEntitledPriority", "(0..15)", ber.ObserveInteger(int64(*v.MaximumEntitledPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximumentitledpriority := ber.EncodeInteger(int64(*v.MaximumEntitledPriority))
		retagged_enc_maximumentitledpriority, tagErr_enc_maximumentitledpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_maximumentitledpriority)
		if tagErr_enc_maximumentitledpriority != nil {
			return nil, qualifyBERError(tagErr_enc_maximumentitledpriority, "maximumEntitledPriority", "encoding", false)
		}
		enc_maximumentitledpriority = retagged_enc_maximumentitledpriority
		children = append(children, enc_maximumentitledpriority...)
	}
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := checkEncodedValue(opts, s7501b7_8, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		retagged_enc_defaultpriority, tagErr_enc_defaultpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_defaultpriority)
		if tagErr_enc_defaultpriority != nil {
			return nil, qualifyBERError(tagErr_enc_defaultpriority, "defaultPriority", "encoding", false)
		}
		enc_defaultpriority = retagged_enc_defaultpriority
		children = append(children, enc_defaultpriority...)
	}
	if v.CcbsFeatureList != nil {
		if len((v.CcbsFeatureList).Values) < 1 || len((v.CcbsFeatureList).Values) > 5 {
			if constraintErr := checkEncodedLength(opts, s7501b7_8, "51.5", "ccbs-FeatureList", "SIZE (1..5)", len((v.CcbsFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsfeaturelist, err := MarshalBERSSCCBSFeatureList(v.CcbsFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "ccbs-FeatureList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "ccbs-FeatureList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berCcbsFeatureListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_ccbsfeaturelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_ccbsfeaturelist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "ccbs-FeatureList", "encoding", false)
				}
			}
		} else {
			retagged_enc_ccbsfeaturelist, tagErr_enc_ccbsfeaturelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsfeaturelist)
			if tagErr_enc_ccbsfeaturelist != nil {
				return nil, qualifyBERError(tagErr_enc_ccbsfeaturelist, "ccbs-FeatureList", "encoding", false)
			}
			enc_ccbsfeaturelist = retagged_enc_ccbsfeaturelist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_ccbsfeaturelist)
		children = append(children, enc_ccbsfeaturelist...)
	}
	if v.NbrSB != nil {
		if !(int64(*v.NbrSB) >= 2 && int64(*v.NbrSB) <= 7) {
			if constraintErr := checkEncodedValue(opts, s7501b7_8, "51.4", "nbrSB", "(2..7)", ber.ObserveInteger(int64(*v.NbrSB))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbrsb := ber.EncodeInteger(int64(*v.NbrSB))
		retagged_enc_nbrsb, tagErr_enc_nbrsb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_nbrsb)
		if tagErr_enc_nbrsb != nil {
			return nil, qualifyBERError(tagErr_enc_nbrsb, "nbrSB", "encoding", false)
		}
		enc_nbrsb = retagged_enc_nbrsb
		children = append(children, enc_nbrsb...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := checkEncodedValue(opts, s7501b7_8, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, qualifyBERError(tagErr_enc_nbruser, "nbrUser", "encoding", false)
		}
		enc_nbruser = retagged_enc_nbruser
		children = append(children, enc_nbruser...)
	}
	if v.NbrSN != nil {
		if !(int64(*v.NbrSN) >= 1 && int64(*v.NbrSN) <= 7) {
			if constraintErr := checkEncodedValue(opts, s7501b7_8, "51.4", "nbrSN", "(1..7)", ber.ObserveInteger(int64(*v.NbrSN))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbrsn := ber.EncodeInteger(int64(*v.NbrSN))
		retagged_enc_nbrsn, tagErr_enc_nbrsn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_nbrsn)
		if tagErr_enc_nbrsn != nil {
			return nil, qualifyBERError(tagErr_enc_nbrsn, "nbrSN", "encoding", false)
		}
		enc_nbrsn = retagged_enc_nbrsn
		children = append(children, enc_nbrsn...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSGenericServiceInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSGenericServiceInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSGenericServiceInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSGenericServiceInfo receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := checkEncodedLength(nil, s7501b7_8, "51.5", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
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
			if constraintErr := checkEncodedValue(nil, s7501b7_8, "20", "cliRestrictionOption", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.CliRestrictionOption))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_clirestrictionoption := ber.EncodeEnumerated(int64(*v.CliRestrictionOption))
		children = append(children, enc_clirestrictionoption...)
	}
	if v.MaximumEntitledPriority != nil {
		if !(int64(*v.MaximumEntitledPriority) >= 0 && int64(*v.MaximumEntitledPriority) <= 15) {
			if constraintErr := checkEncodedValue(nil, s7501b7_8, "51.4", "maximumEntitledPriority", "(0..15)", ber.ObserveInteger(int64(*v.MaximumEntitledPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_maximumentitledpriority := ber.EncodeInteger(int64(*v.MaximumEntitledPriority))
		retagged_enc_maximumentitledpriority, tagErr_enc_maximumentitledpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_maximumentitledpriority)
		if tagErr_enc_maximumentitledpriority != nil {
			return nil, qualifyBERError(tagErr_enc_maximumentitledpriority, "maximumEntitledPriority", "encoding", true)
		}
		enc_maximumentitledpriority = retagged_enc_maximumentitledpriority
		children = append(children, enc_maximumentitledpriority...)
	}
	if v.DefaultPriority != nil {
		if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
			if constraintErr := checkEncodedValue(nil, s7501b7_8, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(*v.DefaultPriority))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_defaultpriority := ber.EncodeInteger(int64(*v.DefaultPriority))
		retagged_enc_defaultpriority, tagErr_enc_defaultpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_defaultpriority)
		if tagErr_enc_defaultpriority != nil {
			return nil, qualifyBERError(tagErr_enc_defaultpriority, "defaultPriority", "encoding", true)
		}
		enc_defaultpriority = retagged_enc_defaultpriority
		children = append(children, enc_defaultpriority...)
	}
	if v.CcbsFeatureList != nil {
		if len((v.CcbsFeatureList).Values) < 1 || len((v.CcbsFeatureList).Values) > 5 {
			if constraintErr := checkEncodedLength(nil, s7501b7_8, "51.5", "ccbs-FeatureList", "SIZE (1..5)", len((v.CcbsFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsfeaturelist, err := MarshalDERSSCCBSFeatureList(v.CcbsFeatureList)
		if err != nil {
			return nil, qualifyBERError(err, "ccbs-FeatureList", "encoding", true)
		}
		retagged_enc_ccbsfeaturelist, tagErr_enc_ccbsfeaturelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ccbsfeaturelist)
		if tagErr_enc_ccbsfeaturelist != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsfeaturelist, "ccbs-FeatureList", "encoding", true)
		}
		enc_ccbsfeaturelist = retagged_enc_ccbsfeaturelist
		children = append(children, enc_ccbsfeaturelist...)
	}
	if v.NbrSB != nil {
		if !(int64(*v.NbrSB) >= 2 && int64(*v.NbrSB) <= 7) {
			if constraintErr := checkEncodedValue(nil, s7501b7_8, "51.4", "nbrSB", "(2..7)", ber.ObserveInteger(int64(*v.NbrSB))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbrsb := ber.EncodeInteger(int64(*v.NbrSB))
		retagged_enc_nbrsb, tagErr_enc_nbrsb := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_nbrsb)
		if tagErr_enc_nbrsb != nil {
			return nil, qualifyBERError(tagErr_enc_nbrsb, "nbrSB", "encoding", true)
		}
		enc_nbrsb = retagged_enc_nbrsb
		children = append(children, enc_nbrsb...)
	}
	if v.NbrUser != nil {
		if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
			if constraintErr := checkEncodedValue(nil, s7501b7_8, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(*v.NbrUser))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbruser := ber.EncodeInteger(int64(*v.NbrUser))
		retagged_enc_nbruser, tagErr_enc_nbruser := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_nbruser)
		if tagErr_enc_nbruser != nil {
			return nil, qualifyBERError(tagErr_enc_nbruser, "nbrUser", "encoding", true)
		}
		enc_nbruser = retagged_enc_nbruser
		children = append(children, enc_nbruser...)
	}
	if v.NbrSN != nil {
		if !(int64(*v.NbrSN) >= 1 && int64(*v.NbrSN) <= 7) {
			if constraintErr := checkEncodedValue(nil, s7501b7_8, "51.4", "nbrSN", "(1..7)", ber.ObserveInteger(int64(*v.NbrSN))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_nbrsn := ber.EncodeInteger(int64(*v.NbrSN))
		retagged_enc_nbrsn, tagErr_enc_nbrsn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_nbrsn)
		if tagErr_enc_nbrsn != nil {
			return nil, qualifyBERError(tagErr_enc_nbrsn, "nbrSN", "encoding", true)
		}
		enc_nbrsn = retagged_enc_nbrsn
		children = append(children, enc_nbrsn...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSGenericServiceInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSGenericServiceInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSGenericServiceInfo from BER/DER format.
func (destination *SSGenericServiceInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSGenericServiceInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSGenericServiceInfo)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_8, "child", (*SSGenericServiceInfo).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSGenericServiceInfo{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSGenericServiceInfo).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSGenericServiceInfo SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSGenericServiceInfo", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Status
	if offset >= len(content) {
		return fmt.Errorf("missing required field ss-Status")
	}
	{
		ber.MarkPreflightTarget(opts, "ss-Status", content[offset:])
		val_ssstatus, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Status", "decoding", false)
		}
		v.SsStatus = SSSSStatus(val_ssstatus)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
			if constraintErr := checkDecodedLength(opts, s7501b7_8, "51.5", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
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
				tmp_clirestrictionoption := SSCliRestrictionOption(val_clirestrictionoption)
				v.CliRestrictionOption = &tmp_clirestrictionoption
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if int64(*v.CliRestrictionOption) != 0 && int64(*v.CliRestrictionOption) != 1 && int64(*v.CliRestrictionOption) != 2 {
					if constraintErr := checkDecodedValue(opts, s7501b7_8, "20", "cliRestrictionOption", "ENUMERATED {0, 1, 2}", ber.ObserveInteger(int64(*v.CliRestrictionOption))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "maximumEntitledPriority", content[offset:])
				decodedTag_maximumentitledpriority, n_maximumentitledpriority, rawVal_maximumentitledpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "maximumEntitledPriority", "decoding", false)
				}
				if decodedTag_maximumentitledpriority.Class != tag.ClassContextSpecific || decodedTag_maximumentitledpriority.Number != 0 || decodedTag_maximumentitledpriority.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_maximumentitledpriority), "maximumEntitledPriority", "decoding", false)
				}
				decVal_maximumentitledpriority, intErr := ber.DecodeIntegerValue(rawVal_maximumentitledpriority)
				if intErr != nil {
					return qualifyBERError(intErr, "maximumEntitledPriority", "decoding", false)
				}
				tmp_maximumentitledpriority := v21_map_commondatatypes.CommonDataTypesEMLPPPriority(decVal_maximumentitledpriority)
				v.MaximumEntitledPriority = &tmp_maximumentitledpriority
				if offset < 0 || offset >
					len(content) || n_maximumentitledpriority < 0 || n_maximumentitledpriority >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_maximumentitledpriority
				if !(int64(*v.MaximumEntitledPriority) >= 0 && int64(*v.MaximumEntitledPriority) <= 15) {
					if constraintErr := checkDecodedValue(opts, s7501b7_8, "51.4", "maximumEntitledPriority", "(0..15)", ber.ObserveInteger(int64(*v.MaximumEntitledPriority))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "defaultPriority", content[offset:])
				decodedTag_defaultpriority, n_defaultpriority, rawVal_defaultpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "defaultPriority", "decoding", false)
				}
				if decodedTag_defaultpriority.Class != tag.ClassContextSpecific || decodedTag_defaultpriority.Number != 1 || decodedTag_defaultpriority.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_defaultpriority), "defaultPriority", "decoding", false)
				}
				decVal_defaultpriority, intErr := ber.DecodeIntegerValue(rawVal_defaultpriority)
				if intErr != nil {
					return qualifyBERError(intErr, "defaultPriority", "decoding", false)
				}
				tmp_defaultpriority := v21_map_commondatatypes.CommonDataTypesEMLPPPriority(decVal_defaultpriority)
				v.DefaultPriority = &tmp_defaultpriority
				if offset < 0 || offset >
					len(content) || n_defaultpriority < 0 || n_defaultpriority >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_defaultpriority
				if !(int64(*v.DefaultPriority) >= 0 && int64(*v.DefaultPriority) <= 15) {
					if constraintErr := checkDecodedValue(opts, s7501b7_8, "51.4", "defaultPriority", "(0..15)", ber.ObserveInteger(int64(*v.DefaultPriority))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ccbs-FeatureList
	v.berCcbsFeatureListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "ccbs-FeatureList", content[offset:])
				decodedTag_ccbsfeaturelist, n_ccbsfeaturelist, rawVal_ccbsfeaturelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-FeatureList", "decoding", false)
				}
				if decodedTag_ccbsfeaturelist.Class != tag.ClassContextSpecific || decodedTag_ccbsfeaturelist.Number != 2 || decodedTag_ccbsfeaturelist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsfeaturelist), "ccbs-FeatureList", "decoding", false)
				}
				_ = rawVal_ccbsfeaturelist
				if offset < 0 || offset >
					len(content) || n_ccbsfeaturelist < 0 || n_ccbsfeaturelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_ccbsfeaturelist, reconstructionErr_ccbsfeaturelist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_ccbsfeaturelist])
				if reconstructionErr_ccbsfeaturelist != nil {
					return qualifyBERError(reconstructionErr_ccbsfeaturelist, "ccbs-FeatureList", "decoding", false)
				}
				dec_ccbsfeaturelist, unmErr := UnmarshalBERSSCCBSFeatureList(reconstructed_ccbsfeaturelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "ccbs-FeatureList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "ccbs-FeatureList", "decoding", false)
				}
				v.CcbsFeatureList = dec_ccbsfeaturelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berCcbsFeatureListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_ccbsfeaturelist < 0 || n_ccbsfeaturelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsfeaturelist
				if len((v.CcbsFeatureList).Values) < 1 || len((v.CcbsFeatureList).Values) > 5 {
					if constraintErr := checkDecodedLength(opts, s7501b7_8, "51.5", "ccbs-FeatureList", "SIZE (1..5)", len((v.CcbsFeatureList).Values)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "nbrSB", content[offset:])
				decodedTag_nbrsb, n_nbrsb, rawVal_nbrsb, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "nbrSB", "decoding", false)
				}
				if decodedTag_nbrsb.Class != tag.ClassContextSpecific || decodedTag_nbrsb.Number != 3 || decodedTag_nbrsb.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbrsb), "nbrSB", "decoding", false)
				}
				decVal_nbrsb, intErr := ber.DecodeIntegerValue(rawVal_nbrsb)
				if intErr != nil {
					return qualifyBERError(intErr, "nbrSB", "decoding", false)
				}
				tmp_nbrsb := v21_map_commondatatypes.CommonDataTypesMaxMCBearers(decVal_nbrsb)
				v.NbrSB = &tmp_nbrsb
				if offset < 0 || offset >
					len(content) || n_nbrsb < 0 || n_nbrsb > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nbrsb
				if !(int64(*v.NbrSB) >= 2 && int64(*v.NbrSB) <= 7) {
					if constraintErr := checkDecodedValue(opts, s7501b7_8, "51.4", "nbrSB", "(2..7)", ber.ObserveInteger(int64(*v.NbrSB))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "nbrUser", content[offset:])
				decodedTag_nbruser, n_nbruser, rawVal_nbruser, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "nbrUser", "decoding", false)
				}
				if decodedTag_nbruser.Class != tag.ClassContextSpecific || decodedTag_nbruser.Number != 4 || decodedTag_nbruser.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbruser), "nbrUser", "decoding", false)
				}
				decVal_nbruser, intErr := ber.DecodeIntegerValue(rawVal_nbruser)
				if intErr != nil {
					return qualifyBERError(intErr, "nbrUser", "decoding", false)
				}
				tmp_nbruser := v21_map_commondatatypes.CommonDataTypesMCBearers(decVal_nbruser)
				v.NbrUser = &tmp_nbruser
				if offset < 0 || offset >
					len(content) || n_nbruser < 0 || n_nbruser > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nbruser
				if !(int64(*v.NbrUser) >= 1 && int64(*v.NbrUser) <= 7) {
					if constraintErr := checkDecodedValue(opts, s7501b7_8, "51.4", "nbrUser", "(1..7)", ber.ObserveInteger(int64(*v.NbrUser))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "nbrSN", content[offset:])
				decodedTag_nbrsn, n_nbrsn, rawVal_nbrsn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "nbrSN", "decoding", false)
				}
				if decodedTag_nbrsn.Class != tag.ClassContextSpecific || decodedTag_nbrsn.Number != 5 || decodedTag_nbrsn.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_nbrsn), "nbrSN", "decoding", false)
				}
				decVal_nbrsn, intErr := ber.DecodeIntegerValue(rawVal_nbrsn)
				if intErr != nil {
					return qualifyBERError(intErr, "nbrSN", "decoding", false)
				}
				tmp_nbrsn := v21_map_commondatatypes.CommonDataTypesMCBearers(decVal_nbrsn)
				v.NbrSN = &tmp_nbrsn
				if offset < 0 || offset >
					len(content) || n_nbrsn < 0 || n_nbrsn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_nbrsn
				if !(int64(*v.NbrSN) >= 1 && int64(*v.NbrSN) <= 7) {
					if constraintErr := checkDecodedValue(opts, s7501b7_8, "51.4", "nbrSN", "(1..7)", ber.ObserveInteger(int64(*v.NbrSN))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSGenericServiceInfo", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 10)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSGenericServiceInfo", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_8, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBERSSCCBSFeatureList encodes a SSCCBSFeatureList list to BER.
func MarshalBERSSCCBSFeatureList(collection *SSCCBSFeatureList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSCCBSFeatureList, marshalBERSSCCBSFeatureList, true)

}
func marshalBERSSCCBSFeatureList(collection *SSCCBSFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-SS-DataTypes.marshalBERSSCCBSFeatureList", "51.5", "CCBS-FeatureList", "SIZE (1..5)", len(list)); constraintErr != nil {
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

func appendBERLinearSSCCBSFeatureList(encoder *ber.LinearEncoder, collection *SSCCBSFeatureList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSCCBSFeatureList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSCCBSFeatureList encodes a SSCCBSFeatureList list to DER.
func MarshalDERSSCCBSFeatureList(collection *SSCCBSFeatureList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 5 {
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-SS-DataTypes.CCBS-FeatureList", "51.5", "CCBS-FeatureList", "SIZE (1..5)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSCCBSFeatureList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSCCBSFeatureList(encoder *ber.LinearEncoder, collection *SSCCBSFeatureList) ([]byte, error) {
	encoded, err := MarshalDERSSCCBSFeatureList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSCCBSFeatureList decodes a SSCCBSFeatureList list from BER.
func UnmarshalBERSSCCBSFeatureList(data []byte, opts ...ber.DecodeOption) (returnValue *SSCCBSFeatureList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-SS-DataTypes.CCBS-FeatureList", "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERSSCCBSFeatureList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSCCBSFeatureList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSCCBSFeatureList", Cause: ber.ErrExtraData}
	}
	var result []SSCCBSFeature
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem SSCCBSFeature
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
	if len(result) < 1 || len(result) > 5 {
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-SS-DataTypes.CCBS-FeatureList", "51.5", "CCBS-FeatureList", "SIZE (1..5)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSCCBSFeatureList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSCCBSFeatureList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SSCCBSFeature to BER format.
func (v *SSCCBSFeature) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSCCBSFeature receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSCCBSFeature).MarshalBER, (*SSCCBSFeature).marshalBER, true)

}
func (v *SSCCBSFeature) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CcbsIndex != nil {
		if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
			if constraintErr := checkEncodedValue(opts, s7501b7_9, "51.4", "ccbs-Index", "(1..5)", ber.ObserveInteger(int64(*v.CcbsIndex))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsindex := ber.EncodeInteger(int64(*v.CcbsIndex))
		retagged_enc_ccbsindex, tagErr_enc_ccbsindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsindex)
		if tagErr_enc_ccbsindex != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsindex, "ccbs-Index", "encoding", false)
		}
		enc_ccbsindex = retagged_enc_ccbsindex
		children = append(children, enc_ccbsindex...)
	}
	if v.BSubscriberNumber != nil {
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s7501b7_9, "51.5", "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s7501b7_9, "51.5", "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribernumber, encodeErr_enc_bsubscribernumber := ber.EncodeOctetString([]byte(*v.BSubscriberNumber))
		if encodeErr_enc_bsubscribernumber != nil {
			return nil, qualifyBERError(encodeErr_enc_bsubscribernumber, "b-subscriberNumber", "encoding", false)
		}
		retagged_enc_bsubscribernumber, tagErr_enc_bsubscribernumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_bsubscribernumber)
		if tagErr_enc_bsubscribernumber != nil {
			return nil, qualifyBERError(tagErr_enc_bsubscribernumber, "b-subscriberNumber", "encoding", false)
		}
		enc_bsubscribernumber = retagged_enc_bsubscribernumber
		children = append(children, enc_bsubscribernumber...)
	}
	if v.BSubscriberSubaddress != nil {
		if len(*v.BSubscriberSubaddress) < 1 || len(*v.BSubscriberSubaddress) > 21 {
			if constraintErr := checkEncodedLength(opts, s7501b7_9, "51.5", "b-subscriberSubaddress", "SIZE (1..21)", len(*v.BSubscriberSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribersubaddress, encodeErr_enc_bsubscribersubaddress := ber.EncodeOctetString([]byte(*v.BSubscriberSubaddress))
		if encodeErr_enc_bsubscribersubaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_bsubscribersubaddress, "b-subscriberSubaddress", "encoding", false)
		}
		retagged_enc_bsubscribersubaddress, tagErr_enc_bsubscribersubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_bsubscribersubaddress)
		if tagErr_enc_bsubscribersubaddress != nil {
			return nil, qualifyBERError(tagErr_enc_bsubscribersubaddress, "b-subscriberSubaddress", "encoding", false)
		}
		enc_bsubscribersubaddress = retagged_enc_bsubscribersubaddress
		children = append(children, enc_bsubscribersubaddress...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalBER(ber.ChildEncodeOptions(opts, "basicServiceGroup")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroup", "encoding", false)
		}
		{
			var encodeErr error
			enc_basicservicegroup, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_basicservicegroup)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicServiceGroup", "encoding", false)
			}
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservicegroup)
		children = append(children, enc_basicservicegroup...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSCCBSFeature) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSCCBSFeature to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSCCBSFeature) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSCCBSFeature receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CcbsIndex != nil {
		if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
			if constraintErr := checkEncodedValue(nil, s7501b7_9, "51.4", "ccbs-Index", "(1..5)", ber.ObserveInteger(int64(*v.CcbsIndex))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsindex := ber.EncodeInteger(int64(*v.CcbsIndex))
		retagged_enc_ccbsindex, tagErr_enc_ccbsindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsindex)
		if tagErr_enc_ccbsindex != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsindex, "ccbs-Index", "encoding", true)
		}
		enc_ccbsindex = retagged_enc_ccbsindex
		children = append(children, enc_ccbsindex...)
	}
	if v.BSubscriberNumber != nil {
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
			if constraintErr := checkEncodedLength(nil, s7501b7_9, "51.5", "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s7501b7_9, "51.5", "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribernumber, encodeErr_enc_bsubscribernumber := ber.EncodeOctetString([]byte(*v.BSubscriberNumber))
		if encodeErr_enc_bsubscribernumber != nil {
			return nil, qualifyBERError(encodeErr_enc_bsubscribernumber, "b-subscriberNumber", "encoding", true)
		}
		retagged_enc_bsubscribernumber, tagErr_enc_bsubscribernumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_bsubscribernumber)
		if tagErr_enc_bsubscribernumber != nil {
			return nil, qualifyBERError(tagErr_enc_bsubscribernumber, "b-subscriberNumber", "encoding", true)
		}
		enc_bsubscribernumber = retagged_enc_bsubscribernumber
		children = append(children, enc_bsubscribernumber...)
	}
	if v.BSubscriberSubaddress != nil {
		if len(*v.BSubscriberSubaddress) < 1 || len(*v.BSubscriberSubaddress) > 21 {
			if constraintErr := checkEncodedLength(nil, s7501b7_9, "51.5", "b-subscriberSubaddress", "SIZE (1..21)", len(*v.BSubscriberSubaddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribersubaddress, encodeErr_enc_bsubscribersubaddress := ber.EncodeOctetString([]byte(*v.BSubscriberSubaddress))
		if encodeErr_enc_bsubscribersubaddress != nil {
			return nil, qualifyBERError(encodeErr_enc_bsubscribersubaddress, "b-subscriberSubaddress", "encoding", true)
		}
		retagged_enc_bsubscribersubaddress, tagErr_enc_bsubscribersubaddress := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_bsubscribersubaddress)
		if tagErr_enc_bsubscribersubaddress != nil {
			return nil, qualifyBERError(tagErr_enc_bsubscribersubaddress, "b-subscriberSubaddress", "encoding", true)
		}
		enc_bsubscribersubaddress = retagged_enc_bsubscribersubaddress
		children = append(children, enc_bsubscribersubaddress...)
	}
	if v.BasicServiceGroup != nil {
		enc_basicservicegroup, err := v.BasicServiceGroup.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroup", "encoding", true)
		}
		{
			var encodeErr error
			enc_basicservicegroup, encodeErr = ber.EncodeExplicitTagWithClass(tag.ClassContextSpecific, 3, enc_basicservicegroup)
			if encodeErr != nil {
				return nil, qualifyBERError(encodeErr, "basicServiceGroup", "encoding", true)
			}
		}
		children = append(children, enc_basicservicegroup...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSCCBSFeature as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSCCBSFeature) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSCCBSFeature from BER/DER format.
func (destination *SSCCBSFeature) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSCCBSFeature destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSCCBSFeature)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_9, "child", (*SSCCBSFeature).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSCCBSFeature{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSCCBSFeature).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSCCBSFeature SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "ccbs-Index", content[offset:])
				decodedTag_ccbsindex, n_ccbsindex, rawVal_ccbsindex, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-Index", "decoding", false)
				}
				if decodedTag_ccbsindex.Class != tag.ClassContextSpecific || decodedTag_ccbsindex.Number != 0 || decodedTag_ccbsindex.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsindex), "ccbs-Index", "decoding", false)
				}
				decVal_ccbsindex, intErr := ber.DecodeIntegerValue(rawVal_ccbsindex)
				if intErr != nil {
					return qualifyBERError(intErr, "ccbs-Index", "decoding", false)
				}
				tmp_ccbsindex := SSCCBSIndex(decVal_ccbsindex)
				v.CcbsIndex = &tmp_ccbsindex
				if offset > len(content) || n_ccbsindex < 0 || n_ccbsindex > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsindex
				if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
					if constraintErr := checkDecodedValue(opts, s7501b7_9, "51.4", "ccbs-Index", "(1..5)", ber.ObserveInteger(int64(*v.CcbsIndex))); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "b-subscriberNumber", content[offset:])
				decodedTag_bsubscribernumber, n_bsubscribernumber, rawVal_bsubscribernumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "b-subscriberNumber", "decoding", false)
				}
				if decodedTag_bsubscribernumber.Class != tag.ClassContextSpecific || decodedTag_bsubscribernumber.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bsubscribernumber), "b-subscriberNumber", "decoding", false)
				}
				decVal_bsubscribernumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_bsubscribernumber.Constructed, rawVal_bsubscribernumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "b-subscriberNumber", "decoding", false)
				}
				tmp_bsubscribernumber := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_bsubscribernumber)
				v.BSubscriberNumber = &tmp_bsubscribernumber
				if offset < 0 || offset >
					len(content) || n_bsubscribernumber < 0 || n_bsubscribernumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bsubscribernumber
				if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
					if constraintErr := checkDecodedLength(opts, s7501b7_9, "51.5", "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s7501b7_9, "51.5", "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "b-subscriberSubaddress", content[offset:])
				decodedTag_bsubscribersubaddress, n_bsubscribersubaddress, rawVal_bsubscribersubaddress, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "b-subscriberSubaddress", "decoding", false)
				}
				if decodedTag_bsubscribersubaddress.Class != tag.ClassContextSpecific || decodedTag_bsubscribersubaddress.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bsubscribersubaddress), "b-subscriberSubaddress", "decoding", false)
				}
				decVal_bsubscribersubaddress, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_bsubscribersubaddress.Constructed, rawVal_bsubscribersubaddress, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "b-subscriberSubaddress", "decoding", false)
				}
				tmp_bsubscribersubaddress := v21_map_commondatatypes.CommonDataTypesISDNSubaddressString(decVal_bsubscribersubaddress)
				v.BSubscriberSubaddress = &tmp_bsubscribersubaddress
				if offset < 0 || offset >
					len(content) || n_bsubscribersubaddress < 0 || n_bsubscribersubaddress >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bsubscribersubaddress
				if len(*v.BSubscriberSubaddress) < 1 || len(*v.BSubscriberSubaddress) > 21 {
					if constraintErr := checkDecodedLength(opts, s7501b7_9, "51.5", "b-subscriberSubaddress", "SIZE (1..21)", len(*v.BSubscriberSubaddress)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "basicServiceGroup", content[offset:])
				decodedTag_basicservicegroup, n_basicservicegroup, innerData_basicservicegroup, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "basicServiceGroup", "decoding", false)
				}
				if decodedTag_basicservicegroup.Class != tag.ClassContextSpecific || decodedTag_basicservicegroup.Number != 3 || decodedTag_basicservicegroup.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_basicservicegroup), "basicServiceGroup", "decoding", false)
				}
				_, innerUsed_basicservicegroup, _, innerErr_basicservicegroup := ber.DecodeTLV(innerData_basicservicegroup, opts...)
				if innerErr_basicservicegroup != nil {
					return qualifyBERError(innerErr_basicservicegroup, "basicServiceGroup", "decoding", false)
				}
				if innerUsed_basicservicegroup != len(innerData_basicservicegroup) {
					return qualifyBERError(ber.ErrExtraData, "basicServiceGroup", "decoding", false)
				}
				// Decode inner value from explicit tag wrapper
				ber.MarkPreflightTarget(opts, "basicServiceGroup", innerData_basicservicegroup)
				var dec_basicservicegroup v21_map_commondatatypes.CommonDataTypesBasicServiceCode
				if unmErr := dec_basicservicegroup.UnmarshalBER(innerData_basicservicegroup, ber.ChildDecodeOptions(opts, "basicServiceGroup")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicServiceGroup", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSCCBSFeature", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSCCBSFeature", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_9, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes SSInterrogateSSRes to BER format.
func (v *SSInterrogateSSRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSInterrogateSSRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSInterrogateSSRes).MarshalBER, (*SSInterrogateSSRes).marshalBER, true)

}
func (v *SSInterrogateSSRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SSInterrogateSSRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SSInterrogateSSResChoiceSsStatus:
		if v.SsStatus == nil {
			return nil, fmt.Errorf("%w: choice SSInterrogateSSRes: ss-Status is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "ss-Status", "encoding", false)
		}
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := checkEncodedLength(opts, s7501b7_10, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "ss-Status", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SSInterrogateSSResChoiceBasicServiceGroupList:
		enc_1, err := MarshalBERSSBasicServiceGroupList(v.BasicServiceGroupList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "basicServiceGroupList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", false)
		}
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := checkEncodedLength(opts, s7501b7_10, "51.5", "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "basicServiceGroupList", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SSInterrogateSSResChoiceForwardingFeatureList:
		enc_2, err := MarshalBERSSForwardingFeatureList(v.ForwardingFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "forwardingFeatureList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", false)
		}
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := checkEncodedLength(opts, s7501b7_10, "51.5", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "forwardingFeatureList", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SSInterrogateSSResChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInterrogateSSRes: genericServiceInfo is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.GenericServiceInfo.MarshalBER(ber.ChildEncodeOptions(opts, "genericServiceInfo")...)
		if err != nil {
			return nil, qualifyBERError(err, "genericServiceInfo", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "genericServiceInfo", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SSInterrogateSSRes", v.Choice)
	}
}

// MarshalDER encodes SSInterrogateSSRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSInterrogateSSRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSInterrogateSSRes receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SSInterrogateSSResChoiceBasicServiceGroupList:
		enc_der_1, err := MarshalDERSSBasicServiceGroupList(v.BasicServiceGroupList)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", true)
		}
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := checkEncodedLength(nil, s7501b7_10, "51.5", "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "basicServiceGroupList", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "basicServiceGroupList", "encoding", true)
		}
		return enc_der_1, nil
	case SSInterrogateSSResChoiceForwardingFeatureList:
		enc_der_2, err := MarshalDERSSForwardingFeatureList(v.ForwardingFeatureList)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", true)
		}
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := checkEncodedLength(nil, s7501b7_10, "51.5", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "forwardingFeatureList", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "forwardingFeatureList", "encoding", true)
		}
		return enc_der_2, nil
	case SSInterrogateSSResChoiceGenericServiceInfo:
		if v.GenericServiceInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInterrogateSSRes: genericServiceInfo is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.GenericServiceInfo.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "genericServiceInfo", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "genericServiceInfo", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "genericServiceInfo", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SSInterrogateSSResChoiceSsStatus:
			return nil, qualifyBERError(err, "ss-Status", "encoding", true)
		case SSInterrogateSSResChoiceBasicServiceGroupList:
			return nil, qualifyBERError(err, "basicServiceGroupList", "encoding", true)
		case SSInterrogateSSResChoiceForwardingFeatureList:
			return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", true)
		case SSInterrogateSSResChoiceGenericServiceInfo:
			return nil, qualifyBERError(err, "genericServiceInfo", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SSInterrogateSSRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SSInterrogateSSRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSInterrogateSSRes from BER/DER format.
func (destination *SSInterrogateSSRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSInterrogateSSRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSInterrogateSSRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_10, "child", (*SSInterrogateSSRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSInterrogateSSRes).MarshalBER)
		}

	}()

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSInterrogateSSRes{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSInterrogateSSRes CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSInterrogateSSRes: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SSInterrogateSSRes CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInterrogateSSRes", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSInterrogateSSRes.basicServiceGroupList", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSInterrogateSSRes.forwardingFeatureList", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSInterrogateSSRes.genericServiceInfo", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SSInterrogateSSResChoiceSsStatus
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
		tmp := SSSSStatus(decVal)
		v.SsStatus = &tmp
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := checkDecodedLength(opts, s7501b7_10, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = SSInterrogateSSResChoiceBasicServiceGroupList
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
		dec, unmErr := UnmarshalBERSSBasicServiceGroupList(reconstructed, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "basicServiceGroupList"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "basicServiceGroupList", "decoding", false)
		}
		v.BasicServiceGroupList = dec
		if len((v.BasicServiceGroupList).Values) < 1 || len((v.BasicServiceGroupList).Values) > 13 {
			if constraintErr := checkDecodedLength(opts, s7501b7_10, "51.5", "basicServiceGroupList", "SIZE (1..13)", len((v.BasicServiceGroupList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = SSInterrogateSSResChoiceForwardingFeatureList
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
		dec, unmErr := UnmarshalBERSSForwardingFeatureList(reconstructed, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "forwardingFeatureList"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "forwardingFeatureList", "decoding", false)
		}
		v.ForwardingFeatureList = dec
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := checkDecodedLength(opts, s7501b7_10, "51.5", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 && peekTag.Constructed == true {
		v.Choice = SSInterrogateSSResChoiceGenericServiceInfo
		ber.MarkPreflightTarget(opts, "genericServiceInfo", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "genericServiceInfo", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec SSGenericServiceInfo
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "genericServiceInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "genericServiceInfo", "decoding", false)
		}
		v.GenericServiceInfo = &dec
	} else {
		return fmt.Errorf("unknown tag %s for SSInterrogateSSRes CHOICE", peekTag)
	}
	return nil
}

// MarshalBER encodes SSUSSDArg to BER format.
func (v *SSUSSDArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSUSSDArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSUSSDArg).MarshalBER, (*SSUSSDArg).marshalBER, true)

}
func (v *SSUSSDArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := checkEncodedLength(opts, s7501b7_11, "51.5", "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_ussddatacodingscheme, "ussd-DataCodingScheme", "encoding", false)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := checkEncodedLength(opts, s7501b7_11, "51.5", "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussdstring, encodeErr_enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	if encodeErr_enc_ussdstring != nil {
		return nil, qualifyBERError(encodeErr_enc_ussdstring, "ussd-String", "encoding", false)
	}
	children = append(children, enc_ussdstring...)
	if v.AlertingPattern != nil {
		if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
			if constraintErr := checkEncodedLength(opts, s7501b7_11, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingpattern, encodeErr_enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		if encodeErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(encodeErr_enc_alertingpattern, "alertingPattern", "encoding", false)
		}
		children = append(children, enc_alertingpattern...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkEncodedLength(opts, s7501b7_11, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkEncodedLength(opts, s7501b7_11, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_11, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSUSSDArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSUSSDArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSUSSDArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSUSSDArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := checkEncodedLength(nil, s7501b7_11, "51.5", "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_ussddatacodingscheme, "ussd-DataCodingScheme", "encoding", true)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := checkEncodedLength(nil, s7501b7_11, "51.5", "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussdstring, encodeErr_enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	if encodeErr_enc_ussdstring != nil {
		return nil, qualifyBERError(encodeErr_enc_ussdstring, "ussd-String", "encoding", true)
	}
	children = append(children, enc_ussdstring...)
	if v.AlertingPattern != nil {
		if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
			if constraintErr := checkEncodedLength(nil, s7501b7_11, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_alertingpattern, encodeErr_enc_alertingpattern := ber.EncodeOctetString([]byte(*v.AlertingPattern))
		if encodeErr_enc_alertingpattern != nil {
			return nil, qualifyBERError(encodeErr_enc_alertingpattern, "alertingPattern", "encoding", true)
		}
		children = append(children, enc_alertingpattern...)
	}
	if v.Msisdn != nil {
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
			if constraintErr := checkEncodedLength(nil, s7501b7_11, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
			if constraintErr := checkEncodedLength(nil, s7501b7_11, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.Msisdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_11, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSUSSDArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSUSSDArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSUSSDArg from BER/DER format.
func (destination *SSUSSDArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSUSSDArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSUSSDArg)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_11, "child", (*SSUSSDArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSUSSDArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSUSSDArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSUSSDArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSUSSDArg", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ussd-DataCodingScheme
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-DataCodingScheme")
	}
	{
		ber.MarkPreflightTarget(opts, "ussd-DataCodingScheme", content[offset:])
		val_ussddatacodingscheme, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ussd-DataCodingScheme", "decoding", false)
		}
		v.UssdDataCodingScheme = SSUSSDDataCodingScheme(val_ussddatacodingscheme)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
			if constraintErr := checkDecodedLength(opts, s7501b7_11, "51.5", "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	{
		ber.MarkPreflightTarget(opts, "ussd-String", content[offset:])
		val_ussdstring, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ussd-String", "decoding", false)
		}
		v.UssdString = SSUSSDString(val_ussdstring)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
			if constraintErr := checkDecodedLength(opts, s7501b7_11, "51.5", "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode alertingPattern
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "alertingPattern", content[offset:])
				val_alertingpattern, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "alertingPattern", "decoding", false)
				}
				tmp_alertingpattern := v21_map_commondatatypes.CommonDataTypesAlertingPattern(val_alertingpattern)
				v.AlertingPattern = &tmp_alertingpattern
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.AlertingPattern) < 1 || len(*v.AlertingPattern) > 1 {
					if constraintErr := checkDecodedLength(opts, s7501b7_11, "51.5", "alertingPattern", "SIZE (1)", len(*v.AlertingPattern)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msisdn", "decoding", false)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn), "msisdn", "decoding", false)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msisdn", "decoding", false)
				}
				tmp_msisdn := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_msisdn)
				v.Msisdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 9 {
					if constraintErr := checkDecodedLength(opts, s7501b7_11, "51.5", "msisdn", "SIZE (1..9)", len(*v.Msisdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.Msisdn) < 1 || len(*v.Msisdn) > 20 {
					if constraintErr := checkDecodedLength(opts, s7501b7_11, "51.5", "msisdn", "SIZE (1..20)", len(*v.Msisdn)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSUSSDArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) || (peekTag.Class == tag.ClassUniversal && peekTag.Number == 4)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSUSSDArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_11, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes SSUSSDRes to BER format.
func (v *SSUSSDRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSUSSDRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSUSSDRes).MarshalBER, (*SSUSSDRes).marshalBER, true)

}
func (v *SSUSSDRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := checkEncodedLength(opts, s7501b7_12, "51.5", "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_ussddatacodingscheme, "ussd-DataCodingScheme", "encoding", false)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := checkEncodedLength(opts, s7501b7_12, "51.5", "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussdstring, encodeErr_enc_ussdstring := ber.EncodeOctetString([]byte(v.UssdString))
	if encodeErr_enc_ussdstring != nil {
		return nil, qualifyBERError(encodeErr_enc_ussdstring, "ussd-String", "encoding", false)
	}
	children = append(children, enc_ussdstring...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
func (v *SSUSSDRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSUSSDRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSUSSDRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSUSSDRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
		if constraintErr := checkEncodedLength(nil, s7501b7_12, "51.5", "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ussddatacodingscheme, encodeErr_enc_ussddatacodingscheme := ber.EncodeOctetString([]byte(v.UssdDataCodingScheme))
	if encodeErr_enc_ussddatacodingscheme != nil {
		return nil, qualifyBERError(encodeErr_enc_ussddatacodingscheme, "ussd-DataCodingScheme", "encoding", true)
	}
	children = append(children, enc_ussddatacodingscheme...)
	if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
		if constraintErr := checkEncodedLength(nil, s7501b7_12, "51.5", "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
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
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		children = append(children, ext...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SSUSSDRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSUSSDRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSUSSDRes from BER/DER format.
func (destination *SSUSSDRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSUSSDRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSUSSDRes)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_12, "child", (*SSUSSDRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSUSSDRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSUSSDRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSUSSDRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSUSSDRes", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ussd-DataCodingScheme
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-DataCodingScheme")
	}
	{
		ber.MarkPreflightTarget(opts, "ussd-DataCodingScheme", content[offset:])
		val_ussddatacodingscheme, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ussd-DataCodingScheme", "decoding", false)
		}
		v.UssdDataCodingScheme = SSUSSDDataCodingScheme(val_ussddatacodingscheme)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.UssdDataCodingScheme) < 1 || len(v.UssdDataCodingScheme) > 1 {
			if constraintErr := checkDecodedLength(opts, s7501b7_12, "51.5", "ussd-DataCodingScheme", "SIZE (1)", len(v.UssdDataCodingScheme)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ussd-String
	if offset >= len(content) {
		return fmt.Errorf("missing required field ussd-String")
	}
	{
		ber.MarkPreflightTarget(opts, "ussd-String", content[offset:])
		val_ussdstring, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ussd-String", "decoding", false)
		}
		v.UssdString = SSUSSDString(val_ussdstring)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.UssdString) < 1 || len(v.UssdString) > 160 {
			if constraintErr := checkDecodedLength(opts, s7501b7_12, "51.5", "ussd-String", "SIZE (1..160)", len(v.UssdString)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSUSSDRes", Cause: extErr_}
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

// MarshalBERSSPassword encodes a typed standalone SSPassword, preserving unchanged received BER.
func MarshalBERSSPassword(value *BERValue[SSPassword], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required SSPassword is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERSSPassword, marshalBERSSPassword, false)

}
func marshalBERSSPassword(value *BERValue[SSPassword], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value SSPassword }{Value: value.Value}
	_ = v
	var children []byte
	for _, character := range []byte(v.Value) {
		if !(((character >= ' ' && character <= ' ') || (character >= '0' && character <= '9')) && (character >= '0' && character <= '9')) {
			if constraintErr := checkEncodedValue(opts, "MAP-SS-DataTypes.marshalBERSSPassword", "51.7", "Password", "FROM permitted alphabet", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
				return nil, constraintErr
			}
			break
		}
	}
	if len(v.Value) < 4 || len(v.Value) > 4 {
		if constraintErr := checkEncodedLength(opts, "MAP-SS-DataTypes.marshalBERSSPassword", "51.5", "Password", "SIZE (4)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, stringErr := ber.EncodeStringTagChecked(18, string(v.Value))
	if stringErr != nil {
		return nil, fmt.Errorf("%s: %w", "encoding Password", qualifyBERError(stringErr, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERSSPassword encodes a typed standalone SSPassword using DER.
func MarshalDERSSPassword(value *BERValue[SSPassword]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required SSPassword is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value SSPassword }{Value: value.Value}
	_ = v
	var children []byte
	for _, character := range []byte(v.Value) {
		if !(((character >= ' ' && character <= ' ') || (character >= '0' && character <= '9')) && (character >= '0' && character <= '9')) {
			if constraintErr := checkEncodedValue(nil, s7501b7_13, "51.7", "Password", "FROM permitted alphabet", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
				return nil, constraintErr
			}
			break
		}
	}
	if len(v.Value) < 4 || len(v.Value) > 4 {
		if constraintErr := checkEncodedLength(nil, s7501b7_13, "51.5", "Password", "SIZE (4)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, stringErr := ber.EncodeStringTagChecked(18, string(v.Value))
	if stringErr != nil {
		return nil, fmt.Errorf("%s: %w", "encoding Password", qualifyBERError(stringErr, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERSSPassword decodes one complete typed standalone SSPassword from BER/DER.
func UnmarshalBERSSPassword(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[SSPassword], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, s7501b7_13, "child", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERSSPassword(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	v := &struct{ Value SSPassword }{}
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
				if constraintErr := checkDecodedValue(opts, s7501b7_13, "51.7", "Password", "FROM permitted alphabet", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return constraintErr
				}
				break
			}
		}
		if len(v.Value) < 4 || len(v.Value) > 4 {
			if constraintErr := checkDecodedLength(opts, s7501b7_13, "51.5", "Password", "SIZE (4)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[SSPassword]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSPassword); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERSSSSList encodes a SSSSList list to BER.
func MarshalBERSSSSList(collection *SSSSList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSSSList, marshalBERSSSSList, true)

}
func marshalBERSSSSList(collection *SSSSList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-SS-DataTypes.marshalBERSSSSList", "51.5", "SS-List", "SIZE (1..30)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := checkEncodedLength(opts, "MAP-SS-DataTypes.marshalBERSSSSList", "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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

func appendBERLinearSSSSList(encoder *ber.LinearEncoder, collection *SSSSList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSSSList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSSSList encodes a SSSSList list to DER.
func MarshalDERSSSSList(collection *SSSSList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := checkEncodedCollectionLength(nil, s7501b7_14, "51.5", "SS-List", "SIZE (1..30)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := checkEncodedLength(nil, s7501b7_14, "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSSSList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSSSList(encoder *ber.LinearEncoder, collection *SSSSList) ([]byte, error) {
	encoded, err := MarshalDERSSSSList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSSSList decodes a SSSSList list from BER.
func UnmarshalBERSSSSList(data []byte, opts ...ber.DecodeOption) (returnValue *SSSSList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, s7501b7_14, "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERSSSSList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSSSList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSSSList", Cause: ber.ErrExtraData}
	}
	var result []v21_map_ss_code.SSSSCode
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
			if constraintErr := checkDecodedLength(opts, s7501b7_14, "51.5", fmt.Sprintf("element[%d]", len(result)), "SIZE (1)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, v21_map_ss_code.SSSSCode(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 30 {
		if constraintErr := checkDecodedCollectionLength(opts, s7501b7_14, "51.5", "SS-List", "SIZE (1..30)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSSSList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSSSList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERSSSSInfoList encodes a SSSSInfoList list to BER.
func MarshalBERSSSSInfoList(collection *SSSSInfoList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSSSInfoList, marshalBERSSSSInfoList, true)

}
func marshalBERSSSSInfoList(collection *SSSSInfoList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-SS-DataTypes.marshalBERSSSSInfoList", "51.5", "SS-InfoList", "SIZE (1..30)", len(list)); constraintErr != nil {
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

func appendBERLinearSSSSInfoList(encoder *ber.LinearEncoder, collection *SSSSInfoList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSSSInfoList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSSSInfoList encodes a SSSSInfoList list to DER.
func MarshalDERSSSSInfoList(collection *SSSSInfoList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-SS-DataTypes.SS-InfoList", "51.5", "SS-InfoList", "SIZE (1..30)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSSSInfoList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSSSInfoList(encoder *ber.LinearEncoder, collection *SSSSInfoList) ([]byte, error) {
	encoded, err := MarshalDERSSSSInfoList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSSSInfoList decodes a SSSSInfoList list from BER.
func UnmarshalBERSSSSInfoList(data []byte, opts ...ber.DecodeOption) (returnValue *SSSSInfoList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-SS-DataTypes.SS-InfoList", "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERSSSSInfoList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSSSInfoList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSSSInfoList", Cause: ber.ErrExtraData}
	}
	var result []SSSSInfo
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem SSSSInfo
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
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-SS-DataTypes.SS-InfoList", "51.5", "SS-InfoList", "SIZE (1..30)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSSSInfoList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSSSInfoList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERSSBasicServiceGroupList encodes a SSBasicServiceGroupList list to BER.
func MarshalBERSSBasicServiceGroupList(collection *SSBasicServiceGroupList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSBasicServiceGroupList, marshalBERSSBasicServiceGroupList, true)

}
func marshalBERSSBasicServiceGroupList(collection *SSBasicServiceGroupList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-SS-DataTypes.marshalBERSSBasicServiceGroupList", "51.5", "BasicServiceGroupList", "SIZE (1..13)", len(list)); constraintErr != nil {
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

func appendBERLinearSSBasicServiceGroupList(encoder *ber.LinearEncoder, collection *SSBasicServiceGroupList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSBasicServiceGroupList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSBasicServiceGroupList encodes a SSBasicServiceGroupList list to DER.
func MarshalDERSSBasicServiceGroupList(collection *SSBasicServiceGroupList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 13 {
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-SS-DataTypes.BasicServiceGroupList", "51.5", "BasicServiceGroupList", "SIZE (1..13)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSBasicServiceGroupList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSBasicServiceGroupList(encoder *ber.LinearEncoder, collection *SSBasicServiceGroupList) ([]byte, error) {
	encoded, err := MarshalDERSSBasicServiceGroupList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSBasicServiceGroupList decodes a SSBasicServiceGroupList list from BER.
func UnmarshalBERSSBasicServiceGroupList(data []byte, opts ...ber.DecodeOption) (returnValue *SSBasicServiceGroupList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, "MAP-SS-DataTypes.BasicServiceGroupList", "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERSSBasicServiceGroupList(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSBasicServiceGroupList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSBasicServiceGroupList", Cause: ber.ErrExtraData}
	}
	var result []v21_map_commondatatypes.CommonDataTypesBasicServiceCode
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem v21_map_commondatatypes.CommonDataTypesBasicServiceCode
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
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-SS-DataTypes.BasicServiceGroupList", "51.5", "BasicServiceGroupList", "SIZE (1..13)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSBasicServiceGroupList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSBasicServiceGroupList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SSSSInvocationNotificationArg to BER format.
func (v *SSSSInvocationNotificationArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSSSInvocationNotificationArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSSSInvocationNotificationArg).MarshalBER, (*SSSSInvocationNotificationArg).marshalBER, true)

}
func (v *SSSSInvocationNotificationArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, s7501b7_15, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := checkEncodedLength(opts, s7501b7_15, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := checkEncodedLength(opts, s7501b7_15, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", false)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", false)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if len(v.SsEvent) < 1 || len(v.SsEvent) > 1 {
		if constraintErr := checkEncodedLength(opts, s7501b7_15, "51.5", "ss-Event", "SIZE (1)", len(v.SsEvent)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssevent, encodeErr_enc_ssevent := ber.EncodeOctetString([]byte(v.SsEvent))
	if encodeErr_enc_ssevent != nil {
		return nil, qualifyBERError(encodeErr_enc_ssevent, "ss-Event", "encoding", false)
	}
	retagged_enc_ssevent, tagErr_enc_ssevent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ssevent)
	if tagErr_enc_ssevent != nil {
		return nil, qualifyBERError(tagErr_enc_ssevent, "ss-Event", "encoding", false)
	}
	enc_ssevent = retagged_enc_ssevent
	children = append(children, enc_ssevent...)
	if v.SsEventSpecification != nil {
		if len((v.SsEventSpecification).Values) < 1 || len((v.SsEventSpecification).Values) > 2 {
			if constraintErr := checkEncodedLength(opts, s7501b7_15, "51.5", "ss-EventSpecification", "SIZE (1..2)", len((v.SsEventSpecification).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sseventspecification, err := MarshalBERSSSSEventSpecification(v.SsEventSpecification, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "ss-EventSpecification"))...)
		if err != nil {
			return nil, qualifyBERError(err, "ss-EventSpecification", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berSsEventSpecificationIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_sseventspecification)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_sseventspecification, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 3}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "ss-EventSpecification", "encoding", false)
				}
			}
		} else {
			retagged_enc_sseventspecification, tagErr_enc_sseventspecification := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_sseventspecification)
			if tagErr_enc_sseventspecification != nil {
				return nil, qualifyBERError(tagErr_enc_sseventspecification, "ss-EventSpecification", "encoding", false)
			}
			enc_sseventspecification = retagged_enc_sseventspecification
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_sseventspecification)
		children = append(children, enc_sseventspecification...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", false)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	if v.BSubscriberNumber != nil {
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
			if constraintErr := checkEncodedLength(opts, s7501b7_15, "51.5", "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s7501b7_15, "51.5", "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribernumber, encodeErr_enc_bsubscribernumber := ber.EncodeOctetString([]byte(*v.BSubscriberNumber))
		if encodeErr_enc_bsubscribernumber != nil {
			return nil, qualifyBERError(encodeErr_enc_bsubscribernumber, "b-subscriberNumber", "encoding", false)
		}
		retagged_enc_bsubscribernumber, tagErr_enc_bsubscribernumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bsubscribernumber)
		if tagErr_enc_bsubscribernumber != nil {
			return nil, qualifyBERError(tagErr_enc_bsubscribernumber, "b-subscriberNumber", "encoding", false)
		}
		enc_bsubscribernumber = retagged_enc_bsubscribernumber
		children = append(children, enc_bsubscribernumber...)
	}
	if v.CcbsRequestState != nil {
		if int64(*v.CcbsRequestState) != 0 && int64(*v.CcbsRequestState) != 1 && int64(*v.CcbsRequestState) != 2 && int64(*v.CcbsRequestState) != 3 && int64(*v.CcbsRequestState) != 4 && int64(*v.CcbsRequestState) != 5 && int64(*v.CcbsRequestState) != 6 {
			if constraintErr := checkEncodedValue(opts, s7501b7_15, "20", "ccbs-RequestState", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", ber.ObserveInteger(int64(*v.CcbsRequestState))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsrequeststate := ber.EncodeEnumerated(int64(*v.CcbsRequestState))
		retagged_enc_ccbsrequeststate, tagErr_enc_ccbsrequeststate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ccbsrequeststate)
		if tagErr_enc_ccbsrequeststate != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsrequeststate, "ccbs-RequestState", "encoding", false)
		}
		enc_ccbsrequeststate = retagged_enc_ccbsrequeststate
		children = append(children, enc_ccbsrequeststate...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSSSInvocationNotificationArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSSSInvocationNotificationArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSSSInvocationNotificationArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSSInvocationNotificationArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, s7501b7_15, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
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
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
		if constraintErr := checkEncodedLength(nil, s7501b7_15, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
		if constraintErr := checkEncodedLength(nil, s7501b7_15, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.Msisdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msisdn", "encoding", true)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msisdn", "encoding", true)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if len(v.SsEvent) < 1 || len(v.SsEvent) > 1 {
		if constraintErr := checkEncodedLength(nil, s7501b7_15, "51.5", "ss-Event", "SIZE (1)", len(v.SsEvent)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssevent, encodeErr_enc_ssevent := ber.EncodeOctetString([]byte(v.SsEvent))
	if encodeErr_enc_ssevent != nil {
		return nil, qualifyBERError(encodeErr_enc_ssevent, "ss-Event", "encoding", true)
	}
	retagged_enc_ssevent, tagErr_enc_ssevent := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ssevent)
	if tagErr_enc_ssevent != nil {
		return nil, qualifyBERError(tagErr_enc_ssevent, "ss-Event", "encoding", true)
	}
	enc_ssevent = retagged_enc_ssevent
	children = append(children, enc_ssevent...)
	if v.SsEventSpecification != nil {
		if len((v.SsEventSpecification).Values) < 1 || len((v.SsEventSpecification).Values) > 2 {
			if constraintErr := checkEncodedLength(nil, s7501b7_15, "51.5", "ss-EventSpecification", "SIZE (1..2)", len((v.SsEventSpecification).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sseventspecification, err := MarshalDERSSSSEventSpecification(v.SsEventSpecification)
		if err != nil {
			return nil, qualifyBERError(err, "ss-EventSpecification", "encoding", true)
		}
		retagged_enc_sseventspecification, tagErr_enc_sseventspecification := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_sseventspecification)
		if tagErr_enc_sseventspecification != nil {
			return nil, qualifyBERError(tagErr_enc_sseventspecification, "ss-EventSpecification", "encoding", true)
		}
		enc_sseventspecification = retagged_enc_sseventspecification
		children = append(children, enc_sseventspecification...)
	}
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		retagged_enc_extensioncontainer, tagErr_enc_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_extensioncontainer)
		if tagErr_enc_extensioncontainer != nil {
			return nil, qualifyBERError(tagErr_enc_extensioncontainer, "extensionContainer", "encoding", true)
		}
		enc_extensioncontainer = retagged_enc_extensioncontainer
		children = append(children, enc_extensioncontainer...)
	}
	if v.BSubscriberNumber != nil {
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
			if constraintErr := checkEncodedLength(nil, s7501b7_15, "51.5", "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s7501b7_15, "51.5", "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bsubscribernumber, encodeErr_enc_bsubscribernumber := ber.EncodeOctetString([]byte(*v.BSubscriberNumber))
		if encodeErr_enc_bsubscribernumber != nil {
			return nil, qualifyBERError(encodeErr_enc_bsubscribernumber, "b-subscriberNumber", "encoding", true)
		}
		retagged_enc_bsubscribernumber, tagErr_enc_bsubscribernumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_bsubscribernumber)
		if tagErr_enc_bsubscribernumber != nil {
			return nil, qualifyBERError(tagErr_enc_bsubscribernumber, "b-subscriberNumber", "encoding", true)
		}
		enc_bsubscribernumber = retagged_enc_bsubscribernumber
		children = append(children, enc_bsubscribernumber...)
	}
	if v.CcbsRequestState != nil {
		if int64(*v.CcbsRequestState) != 0 && int64(*v.CcbsRequestState) != 1 && int64(*v.CcbsRequestState) != 2 && int64(*v.CcbsRequestState) != 3 && int64(*v.CcbsRequestState) != 4 && int64(*v.CcbsRequestState) != 5 && int64(*v.CcbsRequestState) != 6 {
			if constraintErr := checkEncodedValue(nil, s7501b7_15, "20", "ccbs-RequestState", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", ber.ObserveInteger(int64(*v.CcbsRequestState))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsrequeststate := ber.EncodeEnumerated(int64(*v.CcbsRequestState))
		retagged_enc_ccbsrequeststate, tagErr_enc_ccbsrequeststate := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_ccbsrequeststate)
		if tagErr_enc_ccbsrequeststate != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsrequeststate, "ccbs-RequestState", "encoding", true)
		}
		enc_ccbsrequeststate = retagged_enc_ccbsrequeststate
		children = append(children, enc_ccbsrequeststate...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSSSInvocationNotificationArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSSSInvocationNotificationArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSSSInvocationNotificationArg from BER/DER format.
func (destination *SSSSInvocationNotificationArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSSSInvocationNotificationArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSSSInvocationNotificationArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_15, "child", (*SSSSInvocationNotificationArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSSSInvocationNotificationArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSSSInvocationNotificationArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSSSInvocationNotificationArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "imsi", content[offset:])
		decodedTag_imsi, n_imsi, rawVal_imsi, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "imsi", "decoding", false)
		}
		if decodedTag_imsi.Class != tag.ClassContextSpecific || decodedTag_imsi.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_imsi), "imsi", "decoding", false)
		}
		decVal_imsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_imsi.Constructed, rawVal_imsi, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "imsi", "decoding", false)
		}
		v.Imsi = v21_map_commondatatypes.CommonDataTypesIMSI(decVal_imsi)
		if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_imsi
		if len(v.Imsi) < 3 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, s7501b7_15, "51.5", "imsi", "SIZE (3..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
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
	{
		ber.MarkPreflightTarget(opts, "msisdn", content[offset:])
		decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msisdn", "decoding", false)
		}
		if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_msisdn), "msisdn", "decoding", false)
		}
		decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msisdn", "decoding", false)
		}
		v.Msisdn = v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_msisdn)
		if offset < 0 || offset >
			len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_msisdn
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 9 {
			if constraintErr := checkDecodedLength(opts, s7501b7_15, "51.5", "msisdn", "SIZE (1..9)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Msisdn) < 1 || len(v.Msisdn) > 20 {
			if constraintErr := checkDecodedLength(opts, s7501b7_15, "51.5", "msisdn", "SIZE (1..20)", len(v.Msisdn)); constraintErr != nil {
				return constraintErr
			}
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
	{
		ber.MarkPreflightTarget(opts, "ss-Event", content[offset:])
		decodedTag_ssevent, n_ssevent, rawVal_ssevent, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Event", "decoding", false)
		}
		if decodedTag_ssevent.Class != tag.ClassContextSpecific || decodedTag_ssevent.Number != 2 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssevent), "ss-Event", "decoding", false)
		}
		decVal_ssevent, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssevent.Constructed, rawVal_ssevent, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ss-Event", "decoding", false)
		}
		v.SsEvent = v21_map_ss_code.SSSSCode(decVal_ssevent)
		if offset < 0 || offset >
			len(content) || n_ssevent < 0 || n_ssevent > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_ssevent
		if len(v.SsEvent) < 1 || len(v.SsEvent) > 1 {
			if constraintErr := checkDecodedLength(opts, s7501b7_15, "51.5", "ss-Event", "SIZE (1)", len(v.SsEvent)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ss-EventSpecification
	v.berSsEventSpecificationIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "ss-EventSpecification", content[offset:])
				decodedTag_sseventspecification, n_sseventspecification, rawVal_sseventspecification, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-EventSpecification", "decoding", false)
				}
				if decodedTag_sseventspecification.Class != tag.ClassContextSpecific || decodedTag_sseventspecification.Number != 3 || decodedTag_sseventspecification.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sseventspecification), "ss-EventSpecification", "decoding", false)
				}
				_ = rawVal_sseventspecification
				if offset < 0 || offset >
					len(content) || n_sseventspecification < 0 || n_sseventspecification >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_sseventspecification, reconstructionErr_sseventspecification := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_sseventspecification])
				if reconstructionErr_sseventspecification != nil {
					return qualifyBERError(reconstructionErr_sseventspecification, "ss-EventSpecification", "decoding", false)
				}
				dec_sseventspecification, unmErr := UnmarshalBERSSSSEventSpecification(reconstructed_sseventspecification, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "ss-EventSpecification"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "ss-EventSpecification", "decoding", false)
				}
				v.SsEventSpecification = dec_sseventspecification
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berSsEventSpecificationIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_sseventspecification < 0 || n_sseventspecification >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sseventspecification
				if len((v.SsEventSpecification).Values) < 1 || len((v.SsEventSpecification).Values) > 2 {
					if constraintErr := checkDecodedLength(opts, s7501b7_15, "51.5", "ss-EventSpecification", "SIZE (1..2)", len((v.SsEventSpecification).Values)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				decodedTag_extensioncontainer, n_extensioncontainer, rawVal_extensioncontainer, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "extensionContainer", "decoding", false)
				}
				if decodedTag_extensioncontainer.Class != tag.ClassContextSpecific || decodedTag_extensioncontainer.Number != 4 || decodedTag_extensioncontainer.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_extensioncontainer), "extensionContainer", "decoding", false)
				}
				_ = rawVal_extensioncontainer
				if offset < 0 || offset >
					len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_extensioncontainer, reconstructionErr_extensioncontainer := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_extensioncontainer])
				if reconstructionErr_extensioncontainer != nil {
					return qualifyBERError(reconstructionErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if unmErr := dec_extensioncontainer.UnmarshalBER(reconstructed_extensioncontainer, ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
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
				ber.MarkPreflightTarget(opts, "b-subscriberNumber", content[offset:])
				decodedTag_bsubscribernumber, n_bsubscribernumber, rawVal_bsubscribernumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "b-subscriberNumber", "decoding", false)
				}
				if decodedTag_bsubscribernumber.Class != tag.ClassContextSpecific || decodedTag_bsubscribernumber.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_bsubscribernumber), "b-subscriberNumber", "decoding", false)
				}
				decVal_bsubscribernumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_bsubscribernumber.Constructed, rawVal_bsubscribernumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "b-subscriberNumber", "decoding", false)
				}
				tmp_bsubscribernumber := v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_bsubscribernumber)
				v.BSubscriberNumber = &tmp_bsubscribernumber
				if offset < 0 || offset >
					len(content) || n_bsubscribernumber < 0 || n_bsubscribernumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bsubscribernumber
				if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 9 {
					if constraintErr := checkDecodedLength(opts, s7501b7_15, "51.5", "b-subscriberNumber", "SIZE (1..9)", len(*v.BSubscriberNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.BSubscriberNumber) < 1 || len(*v.BSubscriberNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s7501b7_15, "51.5", "b-subscriberNumber", "SIZE (1..20)", len(*v.BSubscriberNumber)); constraintErr != nil {
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
				ber.MarkPreflightTarget(opts, "ccbs-RequestState", content[offset:])
				decodedTag_ccbsrequeststate, n_ccbsrequeststate, rawVal_ccbsrequeststate, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-RequestState", "decoding", false)
				}
				if decodedTag_ccbsrequeststate.Class != tag.ClassContextSpecific || decodedTag_ccbsrequeststate.Number != 6 || decodedTag_ccbsrequeststate.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsrequeststate), "ccbs-RequestState", "decoding", false)
				}
				decVal_ccbsrequeststate, intErr := ber.DecodeEnumeratedValue(rawVal_ccbsrequeststate)
				if intErr != nil {
					return qualifyBERError(intErr, "ccbs-RequestState", "decoding", false)
				}
				tmp_ccbsrequeststate := SSCCBSRequestState(decVal_ccbsrequeststate)
				v.CcbsRequestState = &tmp_ccbsrequeststate
				if offset < 0 || offset >
					len(content) || n_ccbsrequeststate < 0 || n_ccbsrequeststate > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsrequeststate
				if int64(*v.CcbsRequestState) != 0 && int64(*v.CcbsRequestState) != 1 && int64(*v.CcbsRequestState) != 2 && int64(*v.CcbsRequestState) != 3 && int64(*v.CcbsRequestState) != 4 && int64(*v.CcbsRequestState) != 5 && int64(*v.CcbsRequestState) != 6 {
					if constraintErr := checkDecodedValue(opts, s7501b7_15, "20", "ccbs-RequestState", "ENUMERATED {0, 1, 2, 3, 4, 5, 6}", ber.ObserveInteger(int64(*v.CcbsRequestState))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSSSInvocationNotificationArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && ((peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3)) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSSSInvocationNotificationArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_15, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes SSSSInvocationNotificationRes to BER format.
func (v *SSSSInvocationNotificationRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSSSInvocationNotificationRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSSSInvocationNotificationRes).MarshalBER, (*SSSSInvocationNotificationRes).marshalBER, true)

}
func (v *SSSSInvocationNotificationRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalBER(ber.ChildEncodeOptions(opts, "extensionContainer")...)
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_extensioncontainer)
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSSSInvocationNotificationRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSSSInvocationNotificationRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSSSInvocationNotificationRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSSSInvocationNotificationRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.ExtensionContainer != nil {
		enc_extensioncontainer, err := v.ExtensionContainer.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "extensionContainer", "encoding", true)
		}
		children = append(children, enc_extensioncontainer...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSSSInvocationNotificationRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSSSInvocationNotificationRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSSSInvocationNotificationRes from BER/DER format.
func (destination *SSSSInvocationNotificationRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSSSInvocationNotificationRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSSSInvocationNotificationRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_16, "child", (*SSSSInvocationNotificationRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSSSInvocationNotificationRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSSSInvocationNotificationRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSSSInvocationNotificationRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "extensionContainer", content[offset:])
				// Decode nested SEQUENCE (__asn1pkg_v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer)
				_, n_extensioncontainer, _, tlvErr_extensioncontainer := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_extensioncontainer != nil {
					return qualifyBERError(tlvErr_extensioncontainer, "extensionContainer", "decoding", false)
				}
				var dec_extensioncontainer v21_map_extensiondatatypes.ExtensionDataTypesExtensionContainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_extensioncontainer.UnmarshalBER(content[offset:offset+n_extensioncontainer], ber.ChildDecodeOptions(opts, "extensionContainer")...); unmErr != nil {
					return qualifyBERError(unmErr, "extensionContainer", "decoding", false)
				}
				v.ExtensionContainer = &dec_extensioncontainer
				if offset > len(content) || n_extensioncontainer < 0 || n_extensioncontainer > len(content[offset:]) {
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSSSInvocationNotificationRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSSSInvocationNotificationRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_16, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBERSSSSEventSpecification encodes a SSSSEventSpecification list to BER.
func MarshalBERSSSSEventSpecification(collection *SSSSEventSpecification, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSSSEventSpecification, marshalBERSSSSEventSpecification, true)

}
func marshalBERSSSSEventSpecification(collection *SSSSEventSpecification, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 2 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-SS-DataTypes.marshalBERSSSSEventSpecification", "51.5", "SS-EventSpecification", "SIZE (1..2)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := checkEncodedLength(opts, "MAP-SS-DataTypes.marshalBERSSSSEventSpecification", "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
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

func appendBERLinearSSSSEventSpecification(encoder *ber.LinearEncoder, collection *SSSSEventSpecification, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSSSEventSpecification(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSSSEventSpecification encodes a SSSSEventSpecification list to DER.
func MarshalDERSSSSEventSpecification(collection *SSSSEventSpecification) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 2 {
		if constraintErr := checkEncodedCollectionLength(nil, s7501b7_17, "51.5", "SS-EventSpecification", "SIZE (1..2)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 20 {
			if constraintErr := checkEncodedLength(nil, s7501b7_17, "51.5", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1..20)", len(elem)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSSSEventSpecification as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSSSEventSpecification(encoder *ber.LinearEncoder, collection *SSSSEventSpecification) ([]byte, error) {
	encoded, err := MarshalDERSSSSEventSpecification(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSSSEventSpecification decodes a SSSSEventSpecification list from BER.
func UnmarshalBERSSSSEventSpecification(data []byte, opts ...ber.DecodeOption) (returnValue *SSSSEventSpecification, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareValueBER(data, opts, s7501b7_17, "element", func(data []byte,

		probeOpts []ber.DecodeOption) error {
		_, probeErr := UnmarshalBERSSSSEventSpecification(data, probeOpts...)
		return probeErr
	})
	if prepareErr != nil {
		return nil, prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSSSEventSpecification", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSSSEventSpecification", Cause: ber.ErrExtraData}
	}
	var result []v21_map_commondatatypes.CommonDataTypesAddressString
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
		if len(val) < 1 || len(val) > 20 {
			if constraintErr := checkDecodedLength(opts, s7501b7_17, "51.5", fmt.Sprintf("element[%d]", len(result)), "SIZE (1..20)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, v21_map_commondatatypes.CommonDataTypesAddressString(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 2 {
		if constraintErr := checkDecodedCollectionLength(opts, s7501b7_17, "51.5", "SS-EventSpecification", "SIZE (1..2)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSSSEventSpecification{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSSSEventSpecification); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SSRegisterCCEntryArg to BER format.
func (v *SSRegisterCCEntryArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSRegisterCCEntryArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSRegisterCCEntryArg).MarshalBER, (*SSRegisterCCEntryArg).marshalBER, true)

}
func (v *SSRegisterCCEntryArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, s7501b7_18, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", false)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.CcbsData != nil {
		enc_ccbsdata, err := v.CcbsData.MarshalBER(ber.ChildEncodeOptions(opts, "ccbs-Data")...)
		if err != nil {
			return nil, qualifyBERError(err, "ccbs-Data", "encoding", false)
		}
		retagged_enc_ccbsdata, tagErr_enc_ccbsdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ccbsdata)
		if tagErr_enc_ccbsdata != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsdata, "ccbs-Data", "encoding", false)
		}
		enc_ccbsdata = retagged_enc_ccbsdata
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_ccbsdata)
		children = append(children, enc_ccbsdata...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSRegisterCCEntryArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSRegisterCCEntryArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSRegisterCCEntryArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSRegisterCCEntryArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, s7501b7_18, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", true)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.CcbsData != nil {
		enc_ccbsdata, err := v.CcbsData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "ccbs-Data", "encoding", true)
		}
		retagged_enc_ccbsdata, tagErr_enc_ccbsdata := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ccbsdata)
		if tagErr_enc_ccbsdata != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsdata, "ccbs-Data", "encoding", true)
		}
		enc_ccbsdata = retagged_enc_ccbsdata
		children = append(children, enc_ccbsdata...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSRegisterCCEntryArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSRegisterCCEntryArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSRegisterCCEntryArg from BER/DER format.
func (destination *SSRegisterCCEntryArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSRegisterCCEntryArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSRegisterCCEntryArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_18, "child", (*SSRegisterCCEntryArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSRegisterCCEntryArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSRegisterCCEntryArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSRegisterCCEntryArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
		decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Code", "decoding", false)
		}
		if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode), "ss-Code", "decoding", false)
		}
		decVal_sscode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sscode.Constructed, rawVal_sscode, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ss-Code", "decoding", false)
		}
		v.SsCode = v21_map_ss_code.SSSSCode(decVal_sscode)
		if offset > len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_sscode
		if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
			if constraintErr := checkDecodedLength(opts, s7501b7_18, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ccbs-Data
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "ccbs-Data", content[offset:])
				decodedTag_ccbsdata, n_ccbsdata, rawVal_ccbsdata, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-Data", "decoding", false)
				}
				if decodedTag_ccbsdata.Class != tag.ClassContextSpecific || decodedTag_ccbsdata.Number != 1 || decodedTag_ccbsdata.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsdata), "ccbs-Data", "decoding", false)
				}
				_ = rawVal_ccbsdata
				if offset < 0 || offset >
					len(content) || n_ccbsdata < 0 || n_ccbsdata > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_ccbsdata, reconstructionErr_ccbsdata := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_ccbsdata])
				if reconstructionErr_ccbsdata != nil {
					return qualifyBERError(reconstructionErr_ccbsdata, "ccbs-Data", "decoding", false)
				}
				var dec_ccbsdata SSCCBSData
				if unmErr := dec_ccbsdata.UnmarshalBER(reconstructed_ccbsdata, ber.ChildDecodeOptions(opts, "ccbs-Data")...); unmErr != nil {
					return qualifyBERError(unmErr, "ccbs-Data", "decoding", false)
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSRegisterCCEntryArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSRegisterCCEntryArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_18, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes SSCCBSData to BER format.
func (v *SSCCBSData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSCCBSData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSCCBSData).MarshalBER, (*SSCCBSData).marshalBER, true)

}
func (v *SSCCBSData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_ccbsfeature, err := v.CcbsFeature.MarshalBER(ber.ChildEncodeOptions(opts, "ccbs-Feature")...)
	if err != nil {
		return nil, qualifyBERError(err, "ccbs-Feature", "encoding", false)
	}
	retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsfeature)
	if tagErr_enc_ccbsfeature != nil {
		return nil, qualifyBERError(tagErr_enc_ccbsfeature, "ccbs-Feature", "encoding", false)
	}
	enc_ccbsfeature = retagged_enc_ccbsfeature
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_ccbsfeature)
	children = append(children, enc_ccbsfeature...)
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 9 {
		if constraintErr := checkEncodedLength(opts, s7501b7_19, "51.5", "translatedB-Number", "SIZE (1..9)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, s7501b7_19, "51.5", "translatedB-Number", "SIZE (1..20)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_translatedbnumber, encodeErr_enc_translatedbnumber := ber.EncodeOctetString([]byte(v.TranslatedBNumber))
	if encodeErr_enc_translatedbnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_translatedbnumber, "translatedB-Number", "encoding", false)
	}
	retagged_enc_translatedbnumber, tagErr_enc_translatedbnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_translatedbnumber)
	if tagErr_enc_translatedbnumber != nil {
		return nil, qualifyBERError(tagErr_enc_translatedbnumber, "translatedB-Number", "encoding", false)
	}
	enc_translatedbnumber = retagged_enc_translatedbnumber
	children = append(children, enc_translatedbnumber...)
	if v.ServiceIndicator != nil {
		namedBits_ServiceIndicator, namedBitErr_namedBits_ServiceIndicator := ber.NormalizeNamedBitStringForBEREncoding(*v.ServiceIndicator, []ber.NamedBitSizeSet{{{Min: 2, Max: 32}}}, opts...)
		if namedBitErr_namedBits_ServiceIndicator != nil {
			return nil, qualifyBERError(namedBitErr_namedBits_ServiceIndicator, "serviceIndicator", "encoding", false)
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_ServiceIndicator.Bytes, namedBits_ServiceIndicator.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "serviceIndicator", "encoding", false)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:749
		if namedBits_ServiceIndicator.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_ServiceIndicator).BitLength < 2 || (namedBits_ServiceIndicator).BitLength > 32 {
			if constraintErr := checkEncodedLength(opts, s7501b7_19, "51.5", "serviceIndicator", "SIZE (2..32)", (namedBits_ServiceIndicator).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_serviceindicator, encodeErr_enc_serviceindicator := ber.EncodeBitString(namedBits_ServiceIndicator.Bytes, ber.UnusedBitCount(namedBits_ServiceIndicator.BitLength))
		if encodeErr_enc_serviceindicator != nil {
			return nil, qualifyBERError(encodeErr_enc_serviceindicator, "serviceIndicator", "encoding", false)
		}
		retagged_enc_serviceindicator, tagErr_enc_serviceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_serviceindicator)
		if tagErr_enc_serviceindicator != nil {
			return nil, qualifyBERError(tagErr_enc_serviceindicator, "serviceIndicator", "encoding", false)
		}
		enc_serviceindicator = retagged_enc_serviceindicator
		children = append(children, enc_serviceindicator...)
	}
	enc_callinfo, err := v.CallInfo.MarshalBER(ber.ChildEncodeOptions(opts, "callInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "callInfo", "encoding", false)
	}
	retagged_enc_callinfo, tagErr_enc_callinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_callinfo)
	if tagErr_enc_callinfo != nil {
		return nil, qualifyBERError(tagErr_enc_callinfo, "callInfo", "encoding", false)
	}
	enc_callinfo = retagged_enc_callinfo
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_callinfo)
	children = append(children, enc_callinfo...)
	enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalBER(ber.ChildEncodeOptions(opts, "networkSignalInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "networkSignalInfo", "encoding", false)
	}
	retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_networksignalinfo)
	if tagErr_enc_networksignalinfo != nil {
		return nil, qualifyBERError(tagErr_enc_networksignalinfo, "networkSignalInfo", "encoding", false)
	}
	enc_networksignalinfo = retagged_enc_networksignalinfo
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_networksignalinfo)
	children = append(children, enc_networksignalinfo...)
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
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
func (v *SSCCBSData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSCCBSData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSCCBSData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSCCBSData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_ccbsfeature, err := v.CcbsFeature.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "ccbs-Feature", "encoding", true)
	}
	retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsfeature)
	if tagErr_enc_ccbsfeature != nil {
		return nil, qualifyBERError(tagErr_enc_ccbsfeature, "ccbs-Feature", "encoding", true)
	}
	enc_ccbsfeature = retagged_enc_ccbsfeature
	children = append(children, enc_ccbsfeature...)
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 9 {
		if constraintErr := checkEncodedLength(nil, s7501b7_19, "51.5", "translatedB-Number", "SIZE (1..9)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, s7501b7_19, "51.5", "translatedB-Number", "SIZE (1..20)", len(v.TranslatedBNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_translatedbnumber, encodeErr_enc_translatedbnumber := ber.EncodeOctetString([]byte(v.TranslatedBNumber))
	if encodeErr_enc_translatedbnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_translatedbnumber, "translatedB-Number", "encoding", true)
	}
	retagged_enc_translatedbnumber, tagErr_enc_translatedbnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_translatedbnumber)
	if tagErr_enc_translatedbnumber != nil {
		return nil, qualifyBERError(tagErr_enc_translatedbnumber, "translatedB-Number", "encoding", true)
	}
	enc_translatedbnumber = retagged_enc_translatedbnumber
	children = append(children, enc_translatedbnumber...)
	if v.ServiceIndicator != nil {
		namedBits_ServiceIndicator, namedBitErr_namedBits_ServiceIndicator := ber.NormalizeNamedBitStringForEncoding(*v.ServiceIndicator, []ber.NamedBitSizeSet{{{Min: 2, Max: 32}}})
		if namedBitErr_namedBits_ServiceIndicator != nil {
			return nil, qualifyBERError(namedBitErr_namedBits_ServiceIndicator, "serviceIndicator", "encoding", true)
		}
		if bitStringErr := ber.ValidateBitStringLength(namedBits_ServiceIndicator.Bytes, namedBits_ServiceIndicator.BitLength); bitStringErr != nil {
			return nil, qualifyBERError(bitStringErr, "serviceIndicator", "encoding", true)
		}
		// arithmetic pattern BER_BITSTRING_FIELD: 0 <= bit length before modulo and subtraction; gen/codegen.go:749
		if namedBits_ServiceIndicator.BitLength < 0 {
			return nil, fmt.Errorf("negative bit string length")
		}
		if (namedBits_ServiceIndicator).BitLength < 2 || (namedBits_ServiceIndicator).BitLength > 32 {
			if constraintErr := checkEncodedLength(nil, s7501b7_19, "51.5", "serviceIndicator", "SIZE (2..32)", (namedBits_ServiceIndicator).BitLength); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_serviceindicator, encodeErr_enc_serviceindicator := ber.EncodeDERNamedBitString(namedBits_ServiceIndicator.Bytes, namedBits_ServiceIndicator.BitLength)
		if encodeErr_enc_serviceindicator != nil {
			return nil, qualifyBERError(encodeErr_enc_serviceindicator, "serviceIndicator", "encoding", true)
		}
		retagged_enc_serviceindicator, tagErr_enc_serviceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_serviceindicator)
		if tagErr_enc_serviceindicator != nil {
			return nil, qualifyBERError(tagErr_enc_serviceindicator, "serviceIndicator", "encoding", true)
		}
		enc_serviceindicator = retagged_enc_serviceindicator
		children = append(children, enc_serviceindicator...)
	}
	enc_callinfo, err := v.CallInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "callInfo", "encoding", true)
	}
	retagged_enc_callinfo, tagErr_enc_callinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_callinfo)
	if tagErr_enc_callinfo != nil {
		return nil, qualifyBERError(tagErr_enc_callinfo, "callInfo", "encoding", true)
	}
	enc_callinfo = retagged_enc_callinfo
	children = append(children, enc_callinfo...)
	enc_networksignalinfo, err := v.NetworkSignalInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "networkSignalInfo", "encoding", true)
	}
	retagged_enc_networksignalinfo, tagErr_enc_networksignalinfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_networksignalinfo)
	if tagErr_enc_networksignalinfo != nil {
		return nil, qualifyBERError(tagErr_enc_networksignalinfo, "networkSignalInfo", "encoding", true)
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
		return nil, fmt.Errorf("%s: %w", "encoding SSCCBSData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSCCBSData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSCCBSData from BER/DER format.
func (destination *SSCCBSData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSCCBSData destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSCCBSData)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_19, "child", (*SSCCBSData).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSCCBSData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSCCBSData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSCCBSData SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "ccbs-Feature", content[offset:])
		decodedTag_ccbsfeature, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ccbs-Feature", "decoding", false)
		}
		if decodedTag_ccbsfeature.Class != tag.ClassContextSpecific || decodedTag_ccbsfeature.Number != 0 || decodedTag_ccbsfeature.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsfeature), "ccbs-Feature", "decoding", false)
		}
		_ = rawVal_ccbsfeature
		if offset > len(content) || n_ccbsfeature < 0 || n_ccbsfeature > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		reconstructed_ccbsfeature, reconstructionErr_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_ccbsfeature])
		if reconstructionErr_ccbsfeature != nil {
			return qualifyBERError(reconstructionErr_ccbsfeature, "ccbs-Feature", "decoding", false)
		}
		if unmErr := v.CcbsFeature.UnmarshalBER(reconstructed_ccbsfeature, ber.ChildDecodeOptions(opts, "ccbs-Feature")...); unmErr != nil {
			return qualifyBERError(unmErr, "ccbs-Feature", "decoding", false)
		}
		if offset > len(content) || n_ccbsfeature < 0 || n_ccbsfeature > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_ccbsfeature
	}
	// Decode translatedB-Number
	if offset >= len(content) {
		return fmt.Errorf("missing required field translatedB-Number")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("expected tag [%s %d] for translatedB-Number, got %s", "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "translatedB-Number", content[offset:])
		decodedTag_translatedbnumber, n_translatedbnumber, rawVal_translatedbnumber, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "translatedB-Number", "decoding", false)
		}
		if decodedTag_translatedbnumber.Class != tag.ClassContextSpecific || decodedTag_translatedbnumber.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_translatedbnumber), "translatedB-Number", "decoding", false)
		}
		decVal_translatedbnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_translatedbnumber.Constructed, rawVal_translatedbnumber, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "translatedB-Number", "decoding", false)
		}
		v.TranslatedBNumber = v21_map_commondatatypes.CommonDataTypesISDNAddressString(decVal_translatedbnumber)
		if offset < 0 || offset >
			len(content) || n_translatedbnumber < 0 || n_translatedbnumber >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_translatedbnumber
		if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 9 {
			if constraintErr := checkDecodedLength(opts, s7501b7_19, "51.5", "translatedB-Number", "SIZE (1..9)", len(v.TranslatedBNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.TranslatedBNumber) < 1 || len(v.TranslatedBNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s7501b7_19, "51.5", "translatedB-Number", "SIZE (1..20)", len(v.TranslatedBNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode serviceIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "serviceIndicator", content[offset:])
				decodedTag_serviceindicator, n_serviceindicator, rawVal_serviceindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "serviceIndicator", "decoding", false)
				}
				if decodedTag_serviceindicator.Class != tag.ClassContextSpecific || decodedTag_serviceindicator.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_serviceindicator), "serviceIndicator", "decoding", false)
				}
				bsBytes_serviceindicator, bsUnused_serviceindicator, bsErr := ber.DecodeImplicitBitStringValue(decodedTag_serviceindicator.Constructed, rawVal_serviceindicator, opts...)
				if bsErr != nil {
					return qualifyBERError(bsErr, "serviceIndicator", "decoding", false)
				}
				bsBitLength_serviceindicator, bsLenErr_serviceindicator := ber.BitStringBitLength(len(bsBytes_serviceindicator), bsUnused_serviceindicator)
				if bsLenErr_serviceindicator != nil {
					return qualifyBERError(bsLenErr_serviceindicator, "serviceIndicator", "decoding", false)
				}
				tmp_serviceindicator := runtime.BitString{Bytes: bsBytes_serviceindicator, BitLength: bsBitLength_serviceindicator}
				v.ServiceIndicator = &tmp_serviceindicator
				if offset < 0 || offset >
					len(content) || n_serviceindicator < 0 || n_serviceindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_serviceindicator
				*v.ServiceIndicator = ber.NormalizeNamedBitStringSize(*v.ServiceIndicator, []ber.NamedBitSizeSet{{{Min: 2, Max: 32}}}, opts...)
				if (*v.ServiceIndicator).BitLength < 2 || (*v.ServiceIndicator).BitLength > 32 {
					if constraintErr := checkDecodedLength(opts, s7501b7_19, "51.5", "serviceIndicator", "SIZE (2..32)", (*v.ServiceIndicator).BitLength); constraintErr != nil {
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
	{
		ber.MarkPreflightTarget(opts, "callInfo", content[offset:])
		decodedTag_callinfo, n_callinfo, rawVal_callinfo, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "callInfo", "decoding", false)
		}
		if decodedTag_callinfo.Class != tag.ClassContextSpecific || decodedTag_callinfo.Number != 3 || decodedTag_callinfo.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_callinfo), "callInfo", "decoding", false)
		}
		_ = rawVal_callinfo
		if offset < 0 || offset >
			len(content) || n_callinfo < 0 || n_callinfo > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		reconstructed_callinfo, reconstructionErr_callinfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_callinfo])
		if reconstructionErr_callinfo != nil {
			return qualifyBERError(reconstructionErr_callinfo, "callInfo", "decoding", false)
		}
		if unmErr := v.CallInfo.UnmarshalBER(reconstructed_callinfo, ber.ChildDecodeOptions(opts, "callInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "callInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_callinfo < 0 || n_callinfo > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_callinfo
	}
	// Decode networkSignalInfo
	if offset >= len(content) {
		return fmt.Errorf("missing required field networkSignalInfo")
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("expected tag [%s %d] for networkSignalInfo, got %s", "CONTEXT", 4, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "networkSignalInfo", content[offset:])
		decodedTag_networksignalinfo, n_networksignalinfo, rawVal_networksignalinfo, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "networkSignalInfo", "decoding", false)
		}
		if decodedTag_networksignalinfo.Class != tag.ClassContextSpecific || decodedTag_networksignalinfo.Number != 4 || decodedTag_networksignalinfo.Constructed != true {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_networksignalinfo), "networkSignalInfo", "decoding", false)
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
		if unmErr := v.NetworkSignalInfo.UnmarshalBER(reconstructed_networksignalinfo, ber.ChildDecodeOptions(opts, "networkSignalInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "networkSignalInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_networksignalinfo < 0 || n_networksignalinfo >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_networksignalinfo
	}
	v.ExtCount_ = 0
	v.ExtPresent_ = v.ExtPresent_[:0]
	v.ExtData_ = v.ExtData_[:0]
	for offset < len(content) {
		_, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSCCBSData", Cause: extErr_}
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

// MarshalBER encodes SSRegisterCCEntryRes to BER format.
func (v *SSRegisterCCEntryRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSRegisterCCEntryRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSRegisterCCEntryRes).MarshalBER, (*SSRegisterCCEntryRes).marshalBER, true)

}
func (v *SSRegisterCCEntryRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.CcbsFeature != nil {
		enc_ccbsfeature, err := v.CcbsFeature.MarshalBER(ber.ChildEncodeOptions(opts, "ccbs-Feature")...)
		if err != nil {
			return nil, qualifyBERError(err, "ccbs-Feature", "encoding", false)
		}
		retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsfeature)
		if tagErr_enc_ccbsfeature != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsfeature, "ccbs-Feature", "encoding", false)
		}
		enc_ccbsfeature = retagged_enc_ccbsfeature
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_ccbsfeature)
		children = append(children, enc_ccbsfeature...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSRegisterCCEntryRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSRegisterCCEntryRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSRegisterCCEntryRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSRegisterCCEntryRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.CcbsFeature != nil {
		enc_ccbsfeature, err := v.CcbsFeature.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "ccbs-Feature", "encoding", true)
		}
		retagged_enc_ccbsfeature, tagErr_enc_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_ccbsfeature)
		if tagErr_enc_ccbsfeature != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsfeature, "ccbs-Feature", "encoding", true)
		}
		enc_ccbsfeature = retagged_enc_ccbsfeature
		children = append(children, enc_ccbsfeature...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSRegisterCCEntryRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSRegisterCCEntryRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSRegisterCCEntryRes from BER/DER format.
func (destination *SSRegisterCCEntryRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSRegisterCCEntryRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSRegisterCCEntryRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_20, "child", (*SSRegisterCCEntryRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSRegisterCCEntryRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSRegisterCCEntryRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSRegisterCCEntryRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
				ber.MarkPreflightTarget(opts, "ccbs-Feature", content[offset:])
				decodedTag_ccbsfeature, n_ccbsfeature, rawVal_ccbsfeature, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-Feature", "decoding", false)
				}
				if decodedTag_ccbsfeature.Class != tag.ClassContextSpecific || decodedTag_ccbsfeature.Number != 0 || decodedTag_ccbsfeature.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsfeature), "ccbs-Feature", "decoding", false)
				}
				_ = rawVal_ccbsfeature
				if offset > len(content) || n_ccbsfeature < 0 || n_ccbsfeature > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_ccbsfeature, reconstructionErr_ccbsfeature := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_ccbsfeature])
				if reconstructionErr_ccbsfeature != nil {
					return qualifyBERError(reconstructionErr_ccbsfeature, "ccbs-Feature", "decoding", false)
				}
				var dec_ccbsfeature SSCCBSFeature
				if unmErr := dec_ccbsfeature.UnmarshalBER(reconstructed_ccbsfeature, ber.ChildDecodeOptions(opts, "ccbs-Feature")...); unmErr != nil {
					return qualifyBERError(unmErr, "ccbs-Feature", "decoding", false)
				}
				v.CcbsFeature = &dec_ccbsfeature
				if offset > len(content) || n_ccbsfeature < 0 || n_ccbsfeature > len(content[offset:]) {
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
		peekTag, nExt_, _, extErr_ := ber.DecodeTLV(content[offset:], opts...)
		if extErr_ != nil {
			return &ber.DecodeError{Offset: offset, TypeName: "SSRegisterCCEntryRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSRegisterCCEntryRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_20, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes SSEraseCCEntryArg to BER format.
func (v *SSEraseCCEntryArg) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSEraseCCEntryArg receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSEraseCCEntryArg).MarshalBER, (*SSEraseCCEntryArg).marshalBER, true)

}
func (v *SSEraseCCEntryArg) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, s7501b7_21, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", false)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.CcbsIndex != nil {
		if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
			if constraintErr := checkEncodedValue(opts, s7501b7_21, "51.4", "ccbs-Index", "(1..5)", ber.ObserveInteger(int64(*v.CcbsIndex))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsindex := ber.EncodeInteger(int64(*v.CcbsIndex))
		retagged_enc_ccbsindex, tagErr_enc_ccbsindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ccbsindex)
		if tagErr_enc_ccbsindex != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsindex, "ccbs-Index", "encoding", false)
		}
		enc_ccbsindex = retagged_enc_ccbsindex
		children = append(children, enc_ccbsindex...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_21, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSEraseCCEntryArg) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSEraseCCEntryArg to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSEraseCCEntryArg) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSEraseCCEntryArg receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, s7501b7_21, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", true)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.CcbsIndex != nil {
		if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
			if constraintErr := checkEncodedValue(nil, s7501b7_21, "51.4", "ccbs-Index", "(1..5)", ber.ObserveInteger(int64(*v.CcbsIndex))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ccbsindex := ber.EncodeInteger(int64(*v.CcbsIndex))
		retagged_enc_ccbsindex, tagErr_enc_ccbsindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ccbsindex)
		if tagErr_enc_ccbsindex != nil {
			return nil, qualifyBERError(tagErr_enc_ccbsindex, "ccbs-Index", "encoding", true)
		}
		enc_ccbsindex = retagged_enc_ccbsindex
		children = append(children, enc_ccbsindex...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_21, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSEraseCCEntryArg as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSEraseCCEntryArg) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSEraseCCEntryArg from BER/DER format.
func (destination *SSEraseCCEntryArg) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSEraseCCEntryArg destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSEraseCCEntryArg)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_21, "child", (*SSEraseCCEntryArg).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSEraseCCEntryArg{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSEraseCCEntryArg).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSEraseCCEntryArg SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
		decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Code", "decoding", false)
		}
		if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode), "ss-Code", "decoding", false)
		}
		decVal_sscode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sscode.Constructed, rawVal_sscode, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ss-Code", "decoding", false)
		}
		v.SsCode = v21_map_ss_code.SSSSCode(decVal_sscode)
		if offset > len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_sscode
		if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
			if constraintErr := checkDecodedLength(opts, s7501b7_21, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ccbs-Index
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "ccbs-Index", content[offset:])
				decodedTag_ccbsindex, n_ccbsindex, rawVal_ccbsindex, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ccbs-Index", "decoding", false)
				}
				if decodedTag_ccbsindex.Class != tag.ClassContextSpecific || decodedTag_ccbsindex.Number != 1 || decodedTag_ccbsindex.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ccbsindex), "ccbs-Index", "decoding", false)
				}
				decVal_ccbsindex, intErr := ber.DecodeIntegerValue(rawVal_ccbsindex)
				if intErr != nil {
					return qualifyBERError(intErr, "ccbs-Index", "decoding", false)
				}
				tmp_ccbsindex := SSCCBSIndex(decVal_ccbsindex)
				v.CcbsIndex = &tmp_ccbsindex
				if offset < 0 || offset >
					len(content) || n_ccbsindex < 0 || n_ccbsindex > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ccbsindex
				if !(int64(*v.CcbsIndex) >= 1 && int64(*v.CcbsIndex) <= 5) {
					if constraintErr := checkDecodedValue(opts, s7501b7_21, "51.4", "ccbs-Index", "(1..5)", ber.ObserveInteger(int64(*v.CcbsIndex))); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSEraseCCEntryArg", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSEraseCCEntryArg", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_21, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

// MarshalBER encodes SSEraseCCEntryRes to BER format.
func (v *SSEraseCCEntryRes) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSEraseCCEntryRes receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSEraseCCEntryRes).MarshalBER, (*SSEraseCCEntryRes).marshalBER, true)

}
func (v *SSEraseCCEntryRes) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, s7501b7_22, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", false)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := checkEncodedLength(opts, s7501b7_22, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", false)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", false)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.CheckBEROpaqueElement(ext, opts...); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, n, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, extErr)
		}
		if n != len(ext) {
			return nil, fmt.Errorf("encoding extension %d: %w", i, ber.ErrExtraData)
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(opts, s7501b7_22, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ext...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSEraseCCEntryRes) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSEraseCCEntryRes to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSEraseCCEntryRes) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSEraseCCEntryRes receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, s7501b7_22, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", true)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := checkEncodedLength(nil, s7501b7_22, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_ssstatus != nil {
			return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", true)
		}
		retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_ssstatus)
		if tagErr_enc_ssstatus != nil {
			return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", true)
		}
		enc_ssstatus = retagged_enc_ssstatus
		children = append(children, enc_ssstatus...)
	}
	for i, ext := range v.ExtData_ {
		if err := ber.ValidateDEREncodedElement(ext); err != nil {
			return nil, fmt.Errorf("encoding extension %d: %w", i, err)
		}
		peekTag, _, _, extErr := ber.DecodeEncodedTLV(ext)
		if extErr != nil {
			return nil, extErr
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: only the first addition is restricted.
		if i == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if constraintErr := ber.CheckEncodedValue(ber.EncodeRule(nil, s7501b7_22, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), "ExtData_[0]", "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSEraseCCEntryRes as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSEraseCCEntryRes) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSEraseCCEntryRes from BER/DER format.
func (destination *SSEraseCCEntryRes) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSEraseCCEntryRes destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSEraseCCEntryRes)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	preparedData, preparedOptions, prepareErr := prepareCompositeBER(data, opts, s7501b7_22, "child", (*SSEraseCCEntryRes).UnmarshalBER)
	if prepareErr != nil {
		return prepareErr
	}
	data, opts = preparedData, preparedOptions

	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSEraseCCEntryRes{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSEraseCCEntryRes).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSEraseCCEntryRes SEQUENCE", qualifyBERError(err, "", "decoding", false))
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
	{
		ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
		decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Code", "decoding", false)
		}
		if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_sscode), "ss-Code", "decoding", false)
		}
		decVal_sscode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sscode.Constructed, rawVal_sscode, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ss-Code", "decoding", false)
		}
		v.SsCode = v21_map_ss_code.SSSSCode(decVal_sscode)
		if offset > len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_sscode
		if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
			if constraintErr := checkDecodedLength(opts, s7501b7_22, "51.5", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ss-Status
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "ss-Status", content[offset:])
				decodedTag_ssstatus, n_ssstatus, rawVal_ssstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Status", "decoding", false)
				}
				if decodedTag_ssstatus.Class != tag.ClassContextSpecific || decodedTag_ssstatus.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrInvalidTag, decodedTag_ssstatus), "ss-Status", "decoding", false)
				}
				decVal_ssstatus, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssstatus.Constructed, rawVal_ssstatus, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "ss-Status", "decoding", false)
				}
				tmp_ssstatus := SSSSStatus(decVal_ssstatus)
				v.SsStatus = &tmp_ssstatus
				if offset < 0 || offset >
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := checkDecodedLength(opts, s7501b7_22, "51.5", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			return &ber.DecodeError{Offset: offset, TypeName: "SSEraseCCEntryRes", Cause: extErr_}
		}
		// X.680 (02/2021) §§25.6.1, 25.6.3, 52.7.3 NOTE b: the first unknown addition must differ from trailing OPTIONAL/DEFAULT tags.
		if len(v.ExtData_) == 0 && (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) {
			if !ber.ToleranceEnabled(opts) {
				return &ber.DecodeError{Offset: offset, TypeName: "SSEraseCCEntryRes", Cause: fmt.Errorf("%w: repeated or out-of-order SEQUENCE component tag %s", ber.ErrInvalidTag, peekTag)}
			}
			if orderErr_ := ber.CheckDecodedValue(ber.DecodeRule(opts, s7501b7_22, ber.RuleRef{Document: "ITU-T X.690", Edition: "02/2021", Clause: "8.9.2–8.9.3"}), fmt.Sprintf("ExtData_[%d]", len(v.ExtData_)), "SEQUENCE component order (X.690 (02/2021) §§8.9.2–8.9.3)", peekTag.String()); orderErr_ != nil {
				return orderErr_
			}
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

const (
	s7501b7_0  = "MAP-SS-DataTypes.RegisterSS-Arg"
	s7501b7_1  = "MAP-SS-DataTypes.ForwardingInfo"
	s7501b7_2  = "MAP-SS-DataTypes.ForwardingFeature"
	s7501b7_3  = "MAP-SS-DataTypes.CallBarringInfo"
	s7501b7_4  = "MAP-SS-DataTypes.CallBarringFeature"
	s7501b7_5  = "MAP-SS-DataTypes.SS-Data"
	s7501b7_6  = "MAP-SS-DataTypes.SS-SubscriptionOption"
	s7501b7_7  = "MAP-SS-DataTypes.SS-ForBS-Code"
	s7501b7_8  = "MAP-SS-DataTypes.GenericServiceInfo"
	s7501b7_9  = "MAP-SS-DataTypes.CCBS-Feature"
	s7501b7_10 = "MAP-SS-DataTypes.InterrogateSS-Res"
	s7501b7_11 = "MAP-SS-DataTypes.USSD-Arg"
	s7501b7_12 = "MAP-SS-DataTypes.USSD-Res"
	s7501b7_13 = "MAP-SS-DataTypes.Password"
	s7501b7_14 = "MAP-SS-DataTypes.SS-List"
	s7501b7_15 = "MAP-SS-DataTypes.SS-InvocationNotificationArg"
	s7501b7_16 = "MAP-SS-DataTypes.SS-InvocationNotificationRes"
	s7501b7_17 = "MAP-SS-DataTypes.SS-EventSpecification"
	s7501b7_18 = "MAP-SS-DataTypes.RegisterCC-EntryArg"
	s7501b7_19 = "MAP-SS-DataTypes.CCBS-Data"
	s7501b7_20 = "MAP-SS-DataTypes.RegisterCC-EntryRes"
	s7501b7_21 = "MAP-SS-DataTypes.EraseCC-EntryArg"
	s7501b7_22 = "MAP-SS-DataTypes.EraseCC-EntryRes"
)
