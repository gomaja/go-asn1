// Code generated from ASN.1 module "MAP-DataTypes". DO NOT EDIT.

package gsm0902_v3_11_0

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

// TBCDSTRING represents the ASN.1 type TBCD-STRING (OCTET_STRING).
type TBCDSTRING = []byte

// AddressString represents the ASN.1 type AddressString (OCTET_STRING).
type AddressString = []byte

// IsdnAddressString represents the ASN.1 type IsdnAddressString (OCTET_STRING).
type IsdnAddressString = AddressString

// ExternalSignalInfo represents the ASN.1 type ExternalSignalInfo (SEQUENCE).
type ExternalSignalInfo struct {
	ProtocolId     ProtocolId      `asn1:""`
	SignalInfo     SignalInfo      `asn1:""`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SignalInfo represents the ASN.1 type SignalInfo (OCTET_STRING).
type SignalInfo = []byte

// ProtocolId represents the ASN.1 ENUMERATED type ProtocolId.
type ProtocolId int64

const (
	ProtocolIdGsm0408       ProtocolId = 1
	ProtocolIdGsm0806       ProtocolId = 2
	ProtocolIdGsm0808Bssmap ProtocolId = 3
	ProtocolIdEts3001021    ProtocolId = 4
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v ProtocolId) String() string {
	switch v {
	case ProtocolIdGsm0408:
		return "gsm-0408"
	case ProtocolIdGsm0806:
		return "gsm-0806"
	case ProtocolIdGsm0808Bssmap:
		return "gsm-0808-bssmap"
	case ProtocolIdEts3001021:
		return "ets300102-1"
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

// LocAreaId represents the ASN.1 type LocAreaId (OCTET_STRING).
type LocAreaId = []byte

// LocationInfo choice constants.
const (
	LocationInfoChoiceRoamingNumber = 1
	LocationInfoChoiceMscNumber     = 2
)

// LocationInfo represents the ASN.1 CHOICE type LocationInfo.
type LocationInfo struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode    `json:"-"`
	RoamingNumber  *IsdnAddressString `json:"RoamingNumber,omitempty"`
	MscNumber      *IsdnAddressString `json:"MscNumber,omitempty"`
}

// NewLocationInfoRoamingNumber creates a LocationInfo with the roamingNumber alternative.
func NewLocationInfoRoamingNumber(v IsdnAddressString) LocationInfo {
	return LocationInfo{
		Choice:        LocationInfoChoiceRoamingNumber,
		RoamingNumber: &v,
	}
}

// NewLocationInfoMscNumber creates a LocationInfo with the mscNumber alternative.
func NewLocationInfoMscNumber(v IsdnAddressString) LocationInfo {
	return LocationInfo{
		Choice:    LocationInfoChoiceMscNumber,
		MscNumber: &v,
	}
}

// HlrId represents the ASN.1 type HlrId (OCTET_STRING).
type HlrId = IMSI

// HlrList represents the ASN.1 type HlrList (SEQUENCE_OF).
type HlrList struct {
	Values         []HlrId         `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// LMsId represents the ASN.1 type LMsId (OCTET_STRING).
type LMsId = []byte

// GlobalCellId represents the ASN.1 type GlobalCellId (OCTET_STRING).
type GlobalCellId = []byte

// Category represents the ASN.1 type Category (OCTET_STRING).
type Category = []byte

// EquipStatus represents the ASN.1 ENUMERATED type EquipStatus.
type EquipStatus int64

const (
	EquipStatusWhiteListed EquipStatus = 0
	EquipStatusBlackListed EquipStatus = 1
	EquipStatusGreyListed  EquipStatus = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v EquipStatus) String() string {
	switch v {
	case EquipStatusWhiteListed:
		return "white-listed"
	case EquipStatusBlackListed:
		return "black-listed"
	case EquipStatusGreyListed:
		return "grey-listed"
	default:
		return "unknown"
	}
}

// BearerServiceCode represents the ASN.1 type BearerServiceCode (OCTET_STRING).
type BearerServiceCode = []byte

// BearerServiceList represents the ASN.1 type BearerServiceList (SEQUENCE_OF).
type BearerServiceList struct {
	Values         []BearerServiceCode `json:"Values"`
	berReplayNode_ *ber.ReplayNode     `json:"-"`
}

// TeleserviceCode represents the ASN.1 type TeleserviceCode (OCTET_STRING).
type TeleserviceCode = []byte

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

// SubscriberStatus represents the ASN.1 ENUMERATED type SubscriberStatus.
type SubscriberStatus int64

const (
	SubscriberStatusServiceGranted        SubscriberStatus = 0
	SubscriberStatusOperatorOGCallBarring SubscriberStatus = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v SubscriberStatus) String() string {
	switch v {
	case SubscriberStatusServiceGranted:
		return "serviceGranted"
	case SubscriberStatusOperatorOGCallBarring:
		return "operatorOGCallBarring"
	default:
		return "unknown"
	}
}

// SSCode represents the ASN.1 type SS-Code (OCTET_STRING).
type SSCode = []byte

// SSCodeList represents the ASN.1 type SS-CodeList (SEQUENCE_OF).
type SSCodeList struct {
	Values         []SSCode        `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// SSStatus represents the ASN.1 type SS-Status (OCTET_STRING).
type SSStatus = []byte

// SSInformation choice constants.
const (
	SSInformationChoiceForwardingInfo  = 1
	SSInformationChoiceCallBarringInfo = 2
	SSInformationChoiceCugInformation  = 3
	SSInformationChoiceSsData          = 4
)

// SSInformation represents the ASN.1 CHOICE type SS-Information.
type SSInformation struct {
	Choice          int
	berReplayNode_  *ber.ReplayNode  `json:"-"`
	ForwardingInfo  *ForwardingInfo  `json:"ForwardingInfo,omitempty"`
	CallBarringInfo *CallBarringInfo `json:"CallBarringInfo,omitempty"`
	CugInformation  *CUGInformation  `json:"CugInformation,omitempty"`
	SsData          *SSData          `json:"SsData,omitempty"`
}

// NewSSInformationForwardingInfo creates a SSInformation with the forwardingInfo alternative.
func NewSSInformationForwardingInfo(v ForwardingInfo) SSInformation {
	return SSInformation{
		Choice:         SSInformationChoiceForwardingInfo,
		ForwardingInfo: &v,
	}
}

// NewSSInformationCallBarringInfo creates a SSInformation with the callBarringInfo alternative.
func NewSSInformationCallBarringInfo(v CallBarringInfo) SSInformation {
	return SSInformation{
		Choice:          SSInformationChoiceCallBarringInfo,
		CallBarringInfo: &v,
	}
}

// NewSSInformationCugInformation creates a SSInformation with the cug-Information alternative.
func NewSSInformationCugInformation(v CUGInformation) SSInformation {
	return SSInformation{
		Choice:         SSInformationChoiceCugInformation,
		CugInformation: &v,
	}
}

// NewSSInformationSsData creates a SSInformation with the ss-Data alternative.
func NewSSInformationSsData(v SSData) SSInformation {
	return SSInformation{
		Choice: SSInformationChoiceSsData,
		SsData: &v,
	}
}

// SSInfoList represents the ASN.1 type SS-InfoList (SEQUENCE_OF).
type SSInfoList struct {
	Values         []SSInformation `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// SSData represents the ASN.1 type SS-Data (SEQUENCE).
type SSData struct {
	SsCode               SSCode                `asn1:""`
	SsStatus             *SSStatus             `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	SsSubscriptionOption *SSSubscriptionOption `asn1:",optional" json:"SsSubscriptionOption,omitempty"`
	berReplayNode_       *ber.ReplayNode       `asn1:"-" json:"-"`
}

// SSDataList represents the ASN.1 type SS-DataList (SEQUENCE_OF).
type SSDataList struct {
	Values         []SSData        `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// SSRequest represents the ASN.1 ENUMERATED type SS-Request.
type SSRequest int64

const (
	SSRequestRegistration  SSRequest = 0
	SSRequestErasure       SSRequest = 1
	SSRequestActivation    SSRequest = 2
	SSRequestDeactivation  SSRequest = 3
	SSRequestInterrogation SSRequest = 4
	SSRequestInvoke        SSRequest = 5
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v SSRequest) String() string {
	switch v {
	case SSRequestRegistration:
		return "registration"
	case SSRequestErasure:
		return "erasure"
	case SSRequestActivation:
		return "activation"
	case SSRequestDeactivation:
		return "deactivation"
	case SSRequestInterrogation:
		return "interrogation"
	case SSRequestInvoke:
		return "invoke"
	default:
		return "unknown"
	}
}

// SSSubscriptionOption choice constants.
const (
	SSSubscriptionOptionChoicePerCallBasis                     = 1
	SSSubscriptionOptionChoiceNotificationToHeldRetrievedParty = 2
	SSSubscriptionOptionChoiceUserToUserServiceIndicator       = 3
	SSSubscriptionOptionChoiceMaximumConfereesNumber           = 4
	SSSubscriptionOptionChoiceHuntGroupAccessSelectionOrder    = 5
)

// SSSubscriptionOption represents the ASN.1 CHOICE type SS-SubscriptionOption.
type SSSubscriptionOption struct {
	Choice                           int
	berReplayNode_                   *ber.ReplayNode                `json:"-"`
	PerCallBasis                     *bool                          `json:"PerCallBasis,omitempty"`
	NotificationToHeldRetrievedParty *bool                          `json:"NotificationToHeldRetrievedParty,omitempty"`
	UserToUserServiceIndicator       *UserToUserServiceIndicator    `json:"UserToUserServiceIndicator,omitempty"`
	MaximumConfereesNumber           *MaximumConfereesNumber        `json:"MaximumConfereesNumber,omitempty"`
	HuntGroupAccessSelectionOrder    *HuntGroupAccessSelectionOrder `json:"HuntGroupAccessSelectionOrder,omitempty"`
}

// NewSSSubscriptionOptionPerCallBasis creates a SSSubscriptionOption with the perCallBasis alternative.
func NewSSSubscriptionOptionPerCallBasis(v bool) SSSubscriptionOption {
	return SSSubscriptionOption{
		Choice:       SSSubscriptionOptionChoicePerCallBasis,
		PerCallBasis: &v,
	}
}

// NewSSSubscriptionOptionNotificationToHeldRetrievedParty creates a SSSubscriptionOption with the notificationToHeldRetrievedParty alternative.
func NewSSSubscriptionOptionNotificationToHeldRetrievedParty(v bool) SSSubscriptionOption {
	return SSSubscriptionOption{
		Choice:                           SSSubscriptionOptionChoiceNotificationToHeldRetrievedParty,
		NotificationToHeldRetrievedParty: &v,
	}
}

// NewSSSubscriptionOptionUserToUserServiceIndicator creates a SSSubscriptionOption with the userToUserServiceIndicator alternative.
func NewSSSubscriptionOptionUserToUserServiceIndicator(v UserToUserServiceIndicator) SSSubscriptionOption {
	return SSSubscriptionOption{
		Choice:                     SSSubscriptionOptionChoiceUserToUserServiceIndicator,
		UserToUserServiceIndicator: &v,
	}
}

// NewSSSubscriptionOptionMaximumConfereesNumber creates a SSSubscriptionOption with the maximumConfereesNumber alternative.
func NewSSSubscriptionOptionMaximumConfereesNumber(v MaximumConfereesNumber) SSSubscriptionOption {
	return SSSubscriptionOption{
		Choice:                 SSSubscriptionOptionChoiceMaximumConfereesNumber,
		MaximumConfereesNumber: &v,
	}
}

// NewSSSubscriptionOptionHuntGroupAccessSelectionOrder creates a SSSubscriptionOption with the huntGroupAccessSelectionOrder alternative.
func NewSSSubscriptionOptionHuntGroupAccessSelectionOrder(v HuntGroupAccessSelectionOrder) SSSubscriptionOption {
	return SSSubscriptionOption{
		Choice:                        SSSubscriptionOptionChoiceHuntGroupAccessSelectionOrder,
		HuntGroupAccessSelectionOrder: &v,
	}
}

// ForwardingOptions represents the ASN.1 type ForwardingOptions (OCTET_STRING).
type ForwardingOptions = []byte

// UserToUserServiceIndicator represents the ASN.1 type UserToUserServiceIndicator (OCTET_STRING).
type UserToUserServiceIndicator = []byte

// MaximumConfereesNumber represents the ASN.1 type MaximumConfereesNumber (INTEGER).
type MaximumConfereesNumber = int64

// HuntGroupAccessSelectionOrder represents the ASN.1 ENUMERATED type HuntGroupAccessSelectionOrder.
type HuntGroupAccessSelectionOrder int64

const (
	HuntGroupAccessSelectionOrderRandom     HuntGroupAccessSelectionOrder = 0
	HuntGroupAccessSelectionOrderSequential HuntGroupAccessSelectionOrder = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v HuntGroupAccessSelectionOrder) String() string {
	switch v {
	case HuntGroupAccessSelectionOrderRandom:
		return "random"
	case HuntGroupAccessSelectionOrderSequential:
		return "sequential"
	default:
		return "unknown"
	}
}

// NoReplyConditionTime represents the ASN.1 type NoReplyConditionTime (INTEGER).
type NoReplyConditionTime = int64

// NumberOfConferees represents the ASN.1 type NumberOfConferees (INTEGER).
type NumberOfConferees = int64

// CUGFacilities represents the ASN.1 type CUG-Facilities (OCTET_STRING).
type CUGFacilities = []byte

// CUGInterlock represents the ASN.1 type CUG-Interlock (OCTET_STRING).
type CUGInterlock = []byte

// CUGIndex represents the ASN.1 type CUG-Index (OCTET_STRING).
type CUGIndex = []byte

// CUGOptions represents the ASN.1 type CUG-Options (OCTET_STRING).
type CUGOptions = []byte

// CUGFeature represents the ASN.1 type CUG-Feature (SEQUENCE).
type CUGFeature struct {
	CugInterlock   CUGInterlock    `asn1:""`
	CugIndex       CUGIndex        `asn1:""`
	CugOptions     CUGOptions      `asn1:""`
	SsStatus       SSStatus        `asn1:""`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// CUGFeatureList represents the ASN.1 type CUG-FeatureList (SEQUENCE_OF).
type CUGFeatureList struct {
	Values         []CUGFeature    `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// CUGInformation represents the ASN.1 type CUG-Information (SEQUENCE).
type CUGInformation struct {
	CugFacilities CUGFacilities `asn1:""`
	// Component1 is the anonymous component at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 20.1, 22.1.

	Component1     CUGInformationComponent1 `asn1:""`
	berReplayNode_ *ber.ReplayNode          `asn1:"-" json:"-"`
}

// ForwardingInfo represents the ASN.1 type ForwardingInfo (SEQUENCE).
type ForwardingInfo struct {
	SsCode                         *SSCode                `asn1:",optional" json:"SsCode,omitempty"`
	ForwardingFeatureList          *ForwardingFeatureList `asn1:""`
	berForwardingFeatureListIndef_ bool                   `asn1:"-" json:"-"`
	berReplayNode_                 *ber.ReplayNode        `asn1:"-" json:"-"`
}

// ForwardingData represents the ASN.1 type ForwardingData (SEQUENCE).
type ForwardingData struct {
	ForwardedToNumber IsdnAddressString  `asn1:"tag:5,context,implicit"`
	ForwardingOptions *ForwardingOptions `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	berReplayNode_    *ber.ReplayNode    `asn1:"-" json:"-"`
}

// ForwardingFeature represents the ASN.1 type ForwardingFeature (SEQUENCE).
type ForwardingFeature struct {
	BasicService         *BasicServiceCode     `asn1:",optional" json:"BasicService,omitempty"`
	SsStatus             SSStatus              `asn1:"tag:4,context,implicit"`
	ForwardedToNumber    *IsdnAddressString    `asn1:"tag:5,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	ForwardingOptions    *ForwardingOptions    `asn1:"tag:6,context,implicit,optional" json:"ForwardingOptions,omitempty"`
	NoReplyConditionTime *NoReplyConditionTime `asn1:"tag:7,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	berReplayNode_       *ber.ReplayNode       `asn1:"-" json:"-"`
}

// ForwardingFeatureList represents the ASN.1 type ForwardingFeatureList (SEQUENCE_OF).
type ForwardingFeatureList struct {
	Values         []ForwardingFeature `json:"Values"`
	berReplayNode_ *ber.ReplayNode     `json:"-"`
}

// CallBarringInfo represents the ASN.1 type CallBarringInfo (SEQUENCE).
type CallBarringInfo struct {
	SsCode                          SSCode                  `asn1:""`
	CallBarringFeatureList          *CallBarringFeatureList `asn1:""`
	berCallBarringFeatureListIndef_ bool                    `asn1:"-" json:"-"`
	berReplayNode_                  *ber.ReplayNode         `asn1:"-" json:"-"`
}

// CallBarringFeature represents the ASN.1 type CallBarringFeature (SEQUENCE).
type CallBarringFeature struct {
	BasicServiceCode *BasicServiceCode `asn1:",optional" json:"BasicServiceCode,omitempty"`
	SsStatus         SSStatus          `asn1:"tag:4,context,implicit"`
	berReplayNode_   *ber.ReplayNode   `asn1:"-" json:"-"`
}

// CallBarringFeatureList represents the ASN.1 type CallBarringFeatureList (SEQUENCE_OF).
type CallBarringFeatureList struct {
	Values         []CallBarringFeature `json:"Values"`
	berReplayNode_ *ber.ReplayNode      `json:"-"`
}

// SubscriberData represents the ASN.1 type SubscriberData (SEQUENCE).
type SubscriberData struct {
	MsIsdn                           *IsdnAddressString `asn1:"tag:1,context,implicit,optional" json:"MsIsdn,omitempty"`
	Category                         *Category          `asn1:"tag:2,context,implicit,optional" json:"Category,omitempty"`
	SubscriberStatus                 *SubscriberStatus  `asn1:"tag:3,context,implicit,optional" json:"SubscriberStatus,omitempty"`
	BearerServiceList                *BearerServiceList `asn1:"tag:4,context,implicit,optional" json:"BearerServiceList,omitempty"`
	berBearerServiceListIndef_       bool               `asn1:"-" json:"-"`
	TeleserviceList                  *TeleserviceList   `asn1:"tag:6,context,implicit,optional" json:"TeleserviceList,omitempty"`
	berTeleserviceListIndef_         bool               `asn1:"-" json:"-"`
	ProvisonedSupplServices          *SSInfoList        `asn1:"tag:7,context,implicit,optional" json:"ProvisonedSupplServices,omitempty"`
	berProvisonedSupplServicesIndef_ bool               `asn1:"-" json:"-"`
	berReplayNode_                   *ber.ReplayNode    `asn1:"-" json:"-"`
}

// SSNotification represents the ASN.1 type SS-Notification (OCTET_STRING).
type SSNotification = []byte

// Password choice constants.
const (
	// PasswordChoiceAlternative0 selects the anonymous alternative at zero-based position 0; X.208 (11/1988) §§12.5–12.6, 24.1.
	PasswordChoiceAlternative0 = 1
	// PasswordChoiceAlternative1 selects the anonymous alternative at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 24.1.
	PasswordChoiceAlternative1 = 2
)

// Password represents the ASN.1 CHOICE type Password.
type Password struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	// Alternative0 is the anonymous alternative at zero-based position 0; X.208 (11/1988) §§12.5–12.6, 24.1.
	Alternative0 *string `json:"Alternative0,omitempty"`
	// Alternative1 is the anonymous alternative at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 24.1.
	Alternative1 *string `json:"Alternative1,omitempty"`
}

// NewPasswordAlternative0 creates a Password with the alternative0 alternative.
func NewPasswordAlternative0(v string) Password {
	return Password{
		Choice:       PasswordChoiceAlternative0,
		Alternative0: &v,
	}
}

// NewPasswordAlternative1 creates a Password with the alternative1 alternative.
func NewPasswordAlternative1(v string) Password {
	return Password{
		Choice:       PasswordChoiceAlternative1,
		Alternative1: &v,
	}
}

// GuidanceInfo represents the ASN.1 ENUMERATED type GuidanceInfo.
type GuidanceInfo int64

const (
	GuidanceInfoGuidance0 GuidanceInfo = 0
	GuidanceInfoGuidance1 GuidanceInfo = 1
	GuidanceInfoGuidance2 GuidanceInfo = 2
	GuidanceInfoGuidance3 GuidanceInfo = 3
	GuidanceInfoGuidance4 GuidanceInfo = 4
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v GuidanceInfo) String() string {
	switch v {
	case GuidanceInfoGuidance0:
		return "guidance0"
	case GuidanceInfoGuidance1:
		return "guidance1"
	case GuidanceInfoGuidance2:
		return "guidance2"
	case GuidanceInfoGuidance3:
		return "guidance3"
	case GuidanceInfoGuidance4:
		return "guidance4"
	default:
		return "unknown"
	}
}

// SSUserData represents the ASN.1 type SS-UserData (IA5String).
type SSUserData = string

// CallReference represents the ASN.1 type CallReference (OCTET_STRING).
type CallReference = []byte

// CallType represents the ASN.1 ENUMERATED type CallType.
type CallType int64

const (
	CallTypeIncomingCall         CallType = 0
	CallTypeForwardedCallPortion CallType = 1
	CallTypeReroutedCallPortion  CallType = 2
	CallTypeOutgoingCall         CallType = 3
	CallTypeSsRequest            CallType = 4
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CallType) String() string {
	switch v {
	case CallTypeIncomingCall:
		return "incomingCall"
	case CallTypeForwardedCallPortion:
		return "forwardedCallPortion"
	case CallTypeReroutedCallPortion:
		return "reroutedCallPortion"
	case CallTypeOutgoingCall:
		return "outgoingCall"
	case CallTypeSsRequest:
		return "ss-Request"
	default:
		return "unknown"
	}
}

// SSChargingData represents the ASN.1 type SS-ChargingData (SEQUENCE).
type SSChargingData struct {
	SsCode         SSCode          `asn1:"tag:1,context,implicit"`
	SsRequest      SSRequest       `asn1:"tag:2,context,implicit"`
	Charge         *Charge         `asn1:"tag:3,context,implicit,optional" json:"Charge,omitempty"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SSChargingInfo represents the ASN.1 type SS-ChargingInfo (SEQUENCE_OF).
type SSChargingInfo struct {
	Values         []SSChargingData `json:"Values"`
	berReplayNode_ *ber.ReplayNode  `json:"-"`
}

// CallDuration represents the ASN.1 type CallDuration (INTEGER).
type CallDuration = int64

// CallDateTime represents the ASN.1 type CallDateTime (GeneralizedTime).
type CallDateTime = runtime.GeneralizedTime

// PacketDataVolume represents the ASN.1 type PacketDataVolume (INTEGER).
type PacketDataVolume = int64

// Charge represents the ASN.1 type Charge (INTEGER).
type Charge = int64

// ChargingUnit represents the ASN.1 ENUMERATED type ChargingUnit.
type ChargingUnit int64

const (
	ChargingUnitSpecialDrawingRights ChargingUnit = 0
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v ChargingUnit) String() string {
	switch v {
	case ChargingUnitSpecialDrawingRights:
		return "specialDrawingRights"
	default:
		return "unknown"
	}
}

// CallStatus represents the ASN.1 ENUMERATED type CallStatus.
type CallStatus int64

const (
	CallStatusUndetermined                      CallStatus = 0
	CallStatusSuccessfulNormalTermination       CallStatus = 1
	CallStatusSuccessfulAbnormalTermination     CallStatus = 2
	CallStatusForwarded                         CallStatus = 4
	CallStatusForwardedWithAbnormalTermination  CallStatus = 5
	CallStatusRerouted                          CallStatus = 6
	CallStatusReroutedWithAbnormalTermination   CallStatus = 7
	CallStatusUnsuccessfulNoRadioContact        CallStatus = 8
	CallStatusUnsuccessfulNoResponse            CallStatus = 9
	CallStatusUnsuccessfulBusySubscriber        CallStatus = 10
	CallStatusUnsuccessfulSystemFailed          CallStatus = 11
	CallStatusUnsuccessfulSusbcriptionViolation CallStatus = 12
	CallStatusUnsuccessfulUnsupportedFacility   CallStatus = 13
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CallStatus) String() string {
	switch v {
	case CallStatusUndetermined:
		return "undetermined"
	case CallStatusSuccessfulNormalTermination:
		return "successfulNormalTermination"
	case CallStatusSuccessfulAbnormalTermination:
		return "successfulAbnormalTermination"
	case CallStatusForwarded:
		return "forwarded"
	case CallStatusForwardedWithAbnormalTermination:
		return "forwardedWithAbnormalTermination"
	case CallStatusRerouted:
		return "rerouted"
	case CallStatusReroutedWithAbnormalTermination:
		return "reroutedWithAbnormalTermination"
	case CallStatusUnsuccessfulNoRadioContact:
		return "unsuccessfulNoRadioContact"
	case CallStatusUnsuccessfulNoResponse:
		return "unsuccessfulNoResponse"
	case CallStatusUnsuccessfulBusySubscriber:
		return "unsuccessfulBusySubscriber"
	case CallStatusUnsuccessfulSystemFailed:
		return "unsuccessfulSystemFailed"
	case CallStatusUnsuccessfulSusbcriptionViolation:
		return "unsuccessfulSusbcriptionViolation"
	case CallStatusUnsuccessfulUnsupportedFacility:
		return "unsuccessfulUnsupportedFacility"
	default:
		return "unknown"
	}
}

// NumberOfForwarding represents the ASN.1 type NumberOfForwarding (INTEGER).
type NumberOfForwarding = int64

// ChannelType represents the ASN.1 type ChannelType (OCTET_STRING).
type ChannelType = []byte

// ClassmarkInformation represents the ASN.1 type ClassmarkInformation (OCTET_STRING).
type ClassmarkInformation = []byte

// HandoverPriority represents the ASN.1 type HandoverPriority (OCTET_STRING).
type HandoverPriority = []byte

// HandoverType represents the ASN.1 ENUMERATED type HandoverType.
type HandoverType int64

const (
	HandoverTypeInterBSS HandoverType = 0
	HandoverTypeIntraBSS HandoverType = 1
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v HandoverType) String() string {
	switch v {
	case HandoverTypeInterBSS:
		return "interBSS"
	case HandoverTypeIntraBSS:
		return "intraBSS"
	default:
		return "unknown"
	}
}

// AuthenticationSet represents the ASN.1 type AuthenticationSet (SEQUENCE).
type AuthenticationSet struct {
	Rand           Rand            `asn1:""`
	Sres           Sres            `asn1:""`
	Kc             Kc              `asn1:""`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// Rand represents the ASN.1 type Rand (OCTET_STRING).
type Rand = []byte

// Sres represents the ASN.1 type Sres (OCTET_STRING).
type Sres = []byte

// Kc represents the ASN.1 type Kc (OCTET_STRING).
type Kc = []byte

// Ki represents the ASN.1 type Ki (OCTET_STRING).
type Ki = []byte

// CKSN represents the ASN.1 type CKSN (OCTET_STRING).
type CKSN = []byte

// CipheringMode represents the ASN.1 ENUMERATED type CipheringMode.
type CipheringMode int64

const (
	CipheringModeNoEncryption CipheringMode = 1
	CipheringModeVersion1GSM  CipheringMode = 2
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CipheringMode) String() string {
	switch v {
	case CipheringModeNoEncryption:
		return "noEncryption"
	case CipheringModeVersion1GSM:
		return "version1-GSM"
	default:
		return "unknown"
	}
}

// SMRPDA choice constants.
const (
	SMRPDAChoiceImsi                 = 1
	SMRPDAChoiceLMsId                = 2
	SMRPDAChoiceRoamingNumber        = 3
	SMRPDAChoiceServiceCentreAddress = 4
)

// SMRPDA represents the ASN.1 CHOICE type SM-RP-DA.
type SMRPDA struct {
	Choice               int
	berReplayNode_       *ber.ReplayNode    `json:"-"`
	Imsi                 *IMSI              `json:"Imsi,omitempty"`
	LMsId                *LMsId             `json:"LMsId,omitempty"`
	RoamingNumber        *IsdnAddressString `json:"RoamingNumber,omitempty"`
	ServiceCentreAddress *AddressString     `json:"ServiceCentreAddress,omitempty"`
}

// NewSMRPDAImsi creates a SMRPDA with the imsi alternative.
func NewSMRPDAImsi(v IMSI) SMRPDA {
	return SMRPDA{
		Choice: SMRPDAChoiceImsi,
		Imsi:   &v,
	}
}

// NewSMRPDALMsId creates a SMRPDA with the lMsId alternative.
func NewSMRPDALMsId(v LMsId) SMRPDA {
	return SMRPDA{
		Choice: SMRPDAChoiceLMsId,
		LMsId:  &v,
	}
}

// NewSMRPDARoamingNumber creates a SMRPDA with the roamingNumber alternative.
func NewSMRPDARoamingNumber(v IsdnAddressString) SMRPDA {
	return SMRPDA{
		Choice:        SMRPDAChoiceRoamingNumber,
		RoamingNumber: &v,
	}
}

// NewSMRPDAServiceCentreAddress creates a SMRPDA with the serviceCentreAddress alternative.
func NewSMRPDAServiceCentreAddress(v AddressString) SMRPDA {
	return SMRPDA{
		Choice:               SMRPDAChoiceServiceCentreAddress,
		ServiceCentreAddress: &v,
	}
}

// SMRPOA choice constants.
const (
	SMRPOAChoiceMsIsdn               = 1
	SMRPOAChoiceServiceCentreAddress = 2
)

// SMRPOA represents the ASN.1 CHOICE type SM-RP-OA.
type SMRPOA struct {
	Choice               int
	berReplayNode_       *ber.ReplayNode    `json:"-"`
	MsIsdn               *IsdnAddressString `json:"MsIsdn,omitempty"`
	ServiceCentreAddress *AddressString     `json:"ServiceCentreAddress,omitempty"`
}

// NewSMRPOAMsIsdn creates a SMRPOA with the msIsdn alternative.
func NewSMRPOAMsIsdn(v IsdnAddressString) SMRPOA {
	return SMRPOA{
		Choice: SMRPOAChoiceMsIsdn,
		MsIsdn: &v,
	}
}

// NewSMRPOAServiceCentreAddress creates a SMRPOA with the serviceCentreAddress alternative.
func NewSMRPOAServiceCentreAddress(v AddressString) SMRPOA {
	return SMRPOA{
		Choice:               SMRPOAChoiceServiceCentreAddress,
		ServiceCentreAddress: &v,
	}
}

// SMRPUI represents the ASN.1 type SM-RP-UI (OCTET_STRING).
type SMRPUI = []byte

// TraceReference represents the ASN.1 type TraceReference (OCTET_STRING).
type TraceReference = []byte

// TraceType represents the ASN.1 INTEGER type TraceType with named numbers.
type TraceType int64

const (
	TraceTypeAllEvents   TraceType = 0
	TraceTypeOnlyCalls   TraceType = 1
	TraceTypeEventSet1   TraceType = 2
	TraceTypeEventSet254 TraceType = 255
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v TraceType) String() string {
	switch v {
	case TraceTypeAllEvents:
		return "allEvents"
	case TraceTypeOnlyCalls:
		return "onlyCalls"
	case TraceTypeEventSet1:
		return "eventSet1"
	case TraceTypeEventSet254:
		return "eventSet254"
	default:
		return "unknown"
	}
}

// NetworkResource represents the ASN.1 ENUMERATED type NetworkResource.
type NetworkResource int64

const (
	NetworkResourcePLMN           NetworkResource = 0
	NetworkResourceHLR            NetworkResource = 1
	NetworkResourceVLR            NetworkResource = 2
	NetworkResourcePreviousVLR    NetworkResource = 3
	NetworkResourceControllingMSC NetworkResource = 4
	NetworkResourceVMSC           NetworkResource = 5
	NetworkResourceEIR            NetworkResource = 6
	NetworkResourceRadioSubSystem NetworkResource = 7
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v NetworkResource) String() string {
	switch v {
	case NetworkResourcePLMN:
		return "pLMN"
	case NetworkResourceHLR:
		return "hLR"
	case NetworkResourceVLR:
		return "vLR"
	case NetworkResourcePreviousVLR:
		return "previous-VLR"
	case NetworkResourceControllingMSC:
		return "controlling-MSC"
	case NetworkResourceVMSC:
		return "vMSC"
	case NetworkResourceEIR:
		return "eIR"
	case NetworkResourceRadioSubSystem:
		return "radioSubSystem"
	default:
		return "unknown"
	}
}

// RequestParameter represents the ASN.1 ENUMERATED type RequestParameter.
type RequestParameter int64

const (
	RequestParameterRequestIMSI              RequestParameter = 0
	RequestParameterRequestAuthenticationSet RequestParameter = 1
	RequestParameterRequestSubscriberData    RequestParameter = 2
	RequestParameterRequestCUGInformation    RequestParameter = 3
	RequestParameterRequestKi                RequestParameter = 4
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v RequestParameter) String() string {
	switch v {
	case RequestParameterRequestIMSI:
		return "request-IMSI"
	case RequestParameterRequestAuthenticationSet:
		return "request-AuthenticationSet"
	case RequestParameterRequestSubscriberData:
		return "request-SubscriberData"
	case RequestParameterRequestCUGInformation:
		return "request-CUG-Information"
	case RequestParameterRequestKi:
		return "request-Ki"
	default:
		return "unknown"
	}
}

// RequestParameters represents the ASN.1 type RequestParameters (SEQUENCE_OF).
type RequestParameters struct {
	Values         []RequestParameter `json:"Values"`
	berReplayNode_ *ber.ReplayNode    `json:"-"`
}

// SentParameter choice constants.
const (
	SentParameterChoiceImsi              = 1
	SentParameterChoiceAuthenticationSet = 2
	SentParameterChoiceSusbcriberData    = 3
	SentParameterChoiceCugInformation    = 4
	SentParameterChoiceKi                = 5
)

// SentParameter represents the ASN.1 CHOICE type SentParameter.
type SentParameter struct {
	Choice            int
	berReplayNode_    *ber.ReplayNode    `json:"-"`
	Imsi              *IMSI              `json:"Imsi,omitempty"`
	AuthenticationSet *AuthenticationSet `json:"AuthenticationSet,omitempty"`
	SusbcriberData    *SubscriberData    `json:"SusbcriberData,omitempty"`
	CugInformation    *CUGInformation    `json:"CugInformation,omitempty"`
	Ki                *Ki                `json:"Ki,omitempty"`
}

// NewSentParameterImsi creates a SentParameter with the imsi alternative.
func NewSentParameterImsi(v IMSI) SentParameter {
	return SentParameter{
		Choice: SentParameterChoiceImsi,
		Imsi:   &v,
	}
}

// NewSentParameterAuthenticationSet creates a SentParameter with the authenticationSet alternative.
func NewSentParameterAuthenticationSet(v AuthenticationSet) SentParameter {
	return SentParameter{
		Choice:            SentParameterChoiceAuthenticationSet,
		AuthenticationSet: &v,
	}
}

// NewSentParameterSusbcriberData creates a SentParameter with the susbcriberData alternative.
func NewSentParameterSusbcriberData(v SubscriberData) SentParameter {
	return SentParameter{
		Choice:         SentParameterChoiceSusbcriberData,
		SusbcriberData: &v,
	}
}

// NewSentParameterCugInformation creates a SentParameter with the cug-information alternative.
func NewSentParameterCugInformation(v CUGInformation) SentParameter {
	return SentParameter{
		Choice:         SentParameterChoiceCugInformation,
		CugInformation: &v,
	}
}

// NewSentParameterKi creates a SentParameter with the ki alternative.
func NewSentParameterKi(v Ki) SentParameter {
	return SentParameter{
		Choice: SentParameterChoiceKi,
		Ki:     &v,
	}
}

// SentParameters represents the ASN.1 type SentParameters (SEQUENCE_OF).
type SentParameters struct {
	Values         []SentParameter `json:"Values"`
	berReplayNode_ *ber.ReplayNode `json:"-"`
}

// CmServiceType represents the ASN.1 ENUMERATED type CmServiceType.
type CmServiceType int64

const (
	CmServiceTypeMobileOriginatingCall                CmServiceType = 1
	CmServiceTypeEmergencyCallEstablishment           CmServiceType = 2
	CmServiceTypeShortMessageService                  CmServiceType = 4
	CmServiceTypeSsRequest                            CmServiceType = 8
	CmServiceTypeMobileOriginatingCallReEstablishment CmServiceType = 9
	CmServiceTypeMobileTerminatingCall                CmServiceType = 10
)

// String returns the ASN.1 named label, or "unknown" for an unlisted value.
func (v CmServiceType) String() string {
	switch v {
	case CmServiceTypeMobileOriginatingCall:
		return "mobileOriginatingCall"
	case CmServiceTypeEmergencyCallEstablishment:
		return "emergencyCallEstablishment"
	case CmServiceTypeShortMessageService:
		return "shortMessageService"
	case CmServiceTypeSsRequest:
		return "ss-request"
	case CmServiceTypeMobileOriginatingCallReEstablishment:
		return "mobileOriginatingCallRe-establishment"
	case CmServiceTypeMobileTerminatingCall:
		return "mobileTerminatingCall"
	default:
		return "unknown"
	}
}

// AccessConnectionStatus represents the ASN.1 type AccessConnectionStatus (OCTET_STRING).
type AccessConnectionStatus = []byte

// CUGInformationComponent1 is lifted from an anonymous NamedType at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 20.1, 22.1, 24.1.

// CUGInformationComponent1 choice constants.
const (
	CUGInformationComponent1ChoiceCugFeature     = 1
	CUGInformationComponent1ChoiceCugFeatureList = 2
)

// CUGInformationComponent1 represents the ASN.1 CHOICE type CUG-Information-component1.
type CUGInformationComponent1 struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	CugFeature     *CUGFeature     `json:"CugFeature,omitempty"`
	CugFeatureList *CUGFeatureList `json:"CugFeatureList,omitempty"`
}

// NewCUGInformationComponent1CugFeature creates a CUGInformationComponent1 with the cug-Feature alternative.
func NewCUGInformationComponent1CugFeature(v CUGFeature) CUGInformationComponent1 {
	return CUGInformationComponent1{
		Choice:     CUGInformationComponent1ChoiceCugFeature,
		CugFeature: &v,
	}
}

// NewCUGInformationComponent1CugFeatureList creates a CUGInformationComponent1 with the cug-FeatureList alternative.
func NewCUGInformationComponent1CugFeatureList(v *CUGFeatureList) CUGInformationComponent1 {
	return CUGInformationComponent1{
		Choice:         CUGInformationComponent1ChoiceCugFeatureList,
		CugFeatureList: v,
	}
}

// MarshalBERIsdnAddressString encodes a typed standalone IsdnAddressString, preserving unchanged received BER.
func MarshalBERIsdnAddressString(value *BERValue[IsdnAddressString], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required IsdnAddressString is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERIsdnAddressString, marshalBERIsdnAddressString, 2, UnmarshalBERIsdnAddressString)

}
func marshalBERIsdnAddressString(value *BERValue[IsdnAddressString], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value IsdnAddressString }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 10 {
		if constraintErr := checkEncodedLength(opts, "MAP-DataTypes.marshalBERIsdnAddressString", "37.4", "IsdnAddressString", "SIZE (1..10)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 20 {
		if constraintErr := checkEncodedLength(opts, "MAP-DataTypes.marshalBERIsdnAddressString", "37.4", "IsdnAddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IsdnAddressString", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERIsdnAddressString encodes a typed standalone IsdnAddressString using DER.
func MarshalDERIsdnAddressString(value *BERValue[IsdnAddressString]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required IsdnAddressString is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value IsdnAddressString }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 1 || len(v.Value) > 10 {
		if constraintErr := checkEncodedLength(nil, s581f3f_0, "37.4", "IsdnAddressString", "SIZE (1..10)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 20 {
		if constraintErr := checkEncodedLength(nil, s581f3f_0, "37.4", "IsdnAddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding IsdnAddressString", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERIsdnAddressString decodes one complete typed standalone IsdnAddressString from BER/DER.
func UnmarshalBERIsdnAddressString(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[IsdnAddressString], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERIsdnAddressString(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_0, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value IsdnAddressString }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "IsdnAddressString", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding IsdnAddressString", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = IsdnAddressString(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 1 || len(v.Value) > 10 {
			if constraintErr := checkDecodedLength(opts, s581f3f_0, "37.4", "IsdnAddressString", "SIZE (1..10)", len(v.Value)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.Value) < 1 || len(v.Value) > 20 {
			if constraintErr := checkDecodedLength(opts, s581f3f_0, "37.4", "IsdnAddressString", "SIZE (1..20)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[IsdnAddressString]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERIsdnAddressString); replayErr != nil {
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
		if constraintErr := checkEncodedValue(opts, s581f3f_1, "15", "protocolId", "ENUMERATED {1, 2, 3, 4}", ber.ObserveInteger(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := checkEncodedLength(opts, s581f3f_1, "37.4", "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_signalinfo, "signalInfo", "encoding", false)
	}
	children = append(children, enc_signalinfo...)
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
		if constraintErr := checkEncodedValue(nil, s581f3f_1, "15", "protocolId", "ENUMERATED {1, 2, 3, 4}", ber.ObserveInteger(int64(v.ProtocolId))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_protocolid := ber.EncodeEnumerated(int64(v.ProtocolId))
	children = append(children, enc_protocolid...)
	if len(v.SignalInfo) < 1 || len(v.SignalInfo) > 200 {
		if constraintErr := checkEncodedLength(nil, s581f3f_1, "37.4", "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_signalinfo, encodeErr_enc_signalinfo := ber.EncodeOctetString([]byte(v.SignalInfo))
	if encodeErr_enc_signalinfo != nil {
		return nil, qualifyBERError(encodeErr_enc_signalinfo, "signalInfo", "encoding", true)
	}
	children = append(children, enc_signalinfo...)
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_1, opts)
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
			if constraintErr := checkDecodedValue(opts, s581f3f_1, "15", "protocolId", "ENUMERATED {1, 2, 3, 4}", ber.ObserveInteger(int64(v.ProtocolId))); constraintErr != nil {
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
			if constraintErr := checkDecodedLength(opts, s581f3f_1, "37.4", "signalInfo", "SIZE (1..200)", len(v.SignalInfo)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ExternalSignalInfo", Cause: ber.ErrUnexpectedElement}
	}
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
	if len(v.Value) < 2 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(opts, "MAP-DataTypes.marshalBERIMSI", "37.4", "IMSI", "SIZE (2..8)", len(v.Value)); constraintErr != nil {
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
	if len(v.Value) < 2 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(nil, "MAP-DataTypes.IMSI", "37.4", "IMSI", "SIZE (2..8)", len(v.Value)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.IMSI", opts)
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
		if len(v.Value) < 2 || len(v.Value) > 8 {
			if constraintErr := checkDecodedLength(opts, "MAP-DataTypes.IMSI", "37.4", "IMSI", "SIZE (2..8)", len(v.Value)); constraintErr != nil {
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
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s581f3f_2, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, s581f3f_2, "37.4", "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_2, opts)
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
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, s581f3f_2, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
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
			if constraintErr := checkDecodedLength(opts, s581f3f_2, "37.4", "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(opts, "MAP-DataTypes.marshalBERIMEI", "37.4", "IMEI", "SIZE (8)", len(v.Value)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(nil, "MAP-DataTypes.IMEI", "37.4", "IMEI", "SIZE (8)", len(v.Value)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.IMEI", opts)
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
			if constraintErr := checkDecodedLength(opts, "MAP-DataTypes.IMEI", "37.4", "IMEI", "SIZE (8)", len(v.Value)); constraintErr != nil {
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
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, s581f3f_3, "37.4", "roamingNumber", "SIZE (1..10)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s581f3f_3, "37.4", "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
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
			return nil, fmt.Errorf("%w: choice LocationInfo: mscNumber is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.MscNumber))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "mscNumber", "encoding", false)
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, s581f3f_3, "37.4", "mscNumber", "SIZE (1..10)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s581f3f_3, "37.4", "mscNumber", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "mscNumber", "encoding", false)
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
			return nil, qualifyBERError(err, "mscNumber", "encoding", true)
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_3, opts)
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
		tmp := IsdnAddressString(decVal)
		v.RoamingNumber = &tmp
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, s581f3f_3, "37.4", "roamingNumber", "SIZE (1..10)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s581f3f_3, "37.4", "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = LocationInfoChoiceMscNumber
		ber.MarkPreflightTarget(opts, "mscNumber", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "mscNumber", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "mscNumber", "decoding", false)
		}
		tmp := IsdnAddressString(decVal)
		v.MscNumber = &tmp
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, s581f3f_3, "37.4", "mscNumber", "SIZE (1..10)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s581f3f_3, "37.4", "mscNumber", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for LocationInfo CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBERHlrId encodes a typed standalone HlrId, preserving unchanged received BER.
func MarshalBERHlrId(value *BERValue[HlrId], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required HlrId is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERHlrId, marshalBERHlrId, 2, UnmarshalBERHlrId)

}
func marshalBERHlrId(value *BERValue[HlrId], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value HlrId }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 2 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(opts, "MAP-DataTypes.marshalBERHlrId", "37.4", "HlrId", "SIZE (2..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding HlrId", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERHlrId encodes a typed standalone HlrId using DER.
func MarshalDERHlrId(value *BERValue[HlrId]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required HlrId is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value HlrId }{Value: value.Value}
	_ = v
	var children []byte
	if len(v.Value) < 2 || len(v.Value) > 8 {
		if constraintErr := checkEncodedLength(nil, "MAP-DataTypes.HlrId", "37.4", "HlrId", "SIZE (2..8)", len(v.Value)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := ber.EncodeOctetString([]byte(v.Value))
	if encodeErr_enc_value != nil {
		return nil, fmt.Errorf("%s: %w", "encoding HlrId", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERHlrId decodes one complete typed standalone HlrId from BER/DER.
func UnmarshalBERHlrId(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[HlrId], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERHlrId(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.HlrId", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value HlrId }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "HlrId", content[offset:])
		val_value, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", "decoding HlrId", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = HlrId(val_value)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Value) < 2 || len(v.Value) > 8 {
			if constraintErr := checkDecodedLength(opts, "MAP-DataTypes.HlrId", "37.4", "HlrId", "SIZE (2..8)", len(v.Value)); constraintErr != nil {
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
	decoded := &BERValue[HlrId]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERHlrId); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERHlrList encodes a HlrList list to BER.
func MarshalBERHlrList(collection *HlrList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERHlrList, marshalBERHlrList, 3, UnmarshalBERHlrList)

}
func marshalBERHlrList(collection *HlrList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERHlrList", "37.4", "HlrList", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 2 || len(elem) > 8 {
			if constraintErr := checkEncodedLength(opts, "MAP-DataTypes.marshalBERHlrList", "37.4", fmt.Sprintf("element[%d]", elemIndex), "SIZE (2..8)", len(elem)); constraintErr != nil {
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

func appendBERLinearHlrList(encoder *ber.LinearEncoder, collection *HlrList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERHlrList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERHlrList encodes a HlrList list to DER.
func MarshalDERHlrList(collection *HlrList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 50 {
		if constraintErr := checkEncodedCollectionLength(nil, s581f3f_4, "37.4", "HlrList", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 2 || len(elem) > 8 {
			if constraintErr := checkEncodedLength(nil, s581f3f_4, "37.4", fmt.Sprintf("element[%d]", elemIndex), "SIZE (2..8)", len(elem)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding HlrList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearHlrList(encoder *ber.LinearEncoder, collection *HlrList) ([]byte, error) {
	encoded, err := MarshalDERHlrList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERHlrList decodes a HlrList list from BER.
func UnmarshalBERHlrList(data []byte, opts ...ber.DecodeOption) (returnValue *HlrList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERHlrList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_4, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding HlrList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "HlrList", Cause: ber.ErrExtraData}
	}
	var result []HlrId
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
		if len(val) < 2 || len(val) > 8 {
			if constraintErr := checkDecodedLength(opts, s581f3f_4, "37.4", fmt.Sprintf("element[%d]", len(result)), "SIZE (2..8)", len(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, HlrId(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 50 {
		if constraintErr := checkDecodedCollectionLength(opts, s581f3f_4, "37.4", "HlrList", "SIZE (1..50)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &HlrList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERHlrList); replayErr != nil {
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
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERBearerServiceList", "37.4", "BearerServiceList", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := checkEncodedLength(opts, "MAP-DataTypes.marshalBERBearerServiceList", "37.4", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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
		if constraintErr := checkEncodedCollectionLength(nil, s581f3f_5, "37.4", "BearerServiceList", "SIZE (1..50)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := checkEncodedLength(nil, s581f3f_5, "37.4", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_5, opts)
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
			if constraintErr := checkDecodedLength(opts, s581f3f_5, "37.4", fmt.Sprintf("element[%d]", len(result)), "SIZE (1)", len(val)); constraintErr != nil {
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
		if constraintErr := checkDecodedCollectionLength(opts, s581f3f_5, "37.4", "BearerServiceList", "SIZE (1..50)", len(result)); constraintErr != nil {
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
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERTeleserviceList", "37.4", "TeleserviceList", "SIZE (1..20)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := checkEncodedLength(opts, "MAP-DataTypes.marshalBERTeleserviceList", "37.4", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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
		if constraintErr := checkEncodedCollectionLength(nil, s581f3f_6, "37.4", "TeleserviceList", "SIZE (1..20)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := checkEncodedLength(nil, s581f3f_6, "37.4", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_6, opts)
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
			if constraintErr := checkDecodedLength(opts, s581f3f_6, "37.4", fmt.Sprintf("element[%d]", len(result)), "SIZE (1)", len(val)); constraintErr != nil {
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
		if constraintErr := checkDecodedCollectionLength(opts, s581f3f_6, "37.4", "TeleserviceList", "SIZE (1..20)", len(result)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, s581f3f_7, "37.4", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, s581f3f_7, "37.4", "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_7, opts)
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
			if constraintErr := checkDecodedLength(opts, s581f3f_7, "37.4", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
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
			if constraintErr := checkDecodedLength(opts, s581f3f_7, "37.4", "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
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
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERBasicServiceList", "37.4", "BasicServiceList", "SIZE (1..70)", len(list)); constraintErr != nil {
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
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-DataTypes.BasicServiceList", "37.4", "BasicServiceList", "SIZE (1..70)", len(list)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.BasicServiceList", opts)
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
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-DataTypes.BasicServiceList", "37.4", "BasicServiceList", "SIZE (1..70)", len(result)); constraintErr != nil {
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

// MarshalBERSSCodeList encodes a SSCodeList list to BER.
func MarshalBERSSCodeList(collection *SSCodeList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSCodeList, marshalBERSSCodeList, 3, UnmarshalBERSSCodeList)

}
func marshalBERSSCodeList(collection *SSCodeList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERSSCodeList", "37.4", "SS-CodeList", "SIZE (1..30)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := checkEncodedLength(opts, "MAP-DataTypes.marshalBERSSCodeList", "37.4", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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

func appendBERLinearSSCodeList(encoder *ber.LinearEncoder, collection *SSCodeList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSCodeList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSCodeList encodes a SSCodeList list to DER.
func MarshalDERSSCodeList(collection *SSCodeList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := checkEncodedCollectionLength(nil, s581f3f_8, "37.4", "SS-CodeList", "SIZE (1..30)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if len(elem) < 1 || len(elem) > 1 {
			if constraintErr := checkEncodedLength(nil, s581f3f_8, "37.4", fmt.Sprintf("element[%d]", elemIndex), "SIZE (1)", len(elem)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSCodeList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSCodeList(encoder *ber.LinearEncoder, collection *SSCodeList) ([]byte, error) {
	encoded, err := MarshalDERSSCodeList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSCodeList decodes a SSCodeList list from BER.
func UnmarshalBERSSCodeList(data []byte, opts ...ber.DecodeOption) (returnValue *SSCodeList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERSSCodeList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_8, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSCodeList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSCodeList", Cause: ber.ErrExtraData}
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
			if constraintErr := checkDecodedLength(opts, s581f3f_8, "37.4", fmt.Sprintf("element[%d]", len(result)), "SIZE (1)", len(val)); constraintErr != nil {
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
		if constraintErr := checkDecodedCollectionLength(opts, s581f3f_8, "37.4", "SS-CodeList", "SIZE (1..30)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSCodeList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSCodeList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SSInformation to BER format.
func (v *SSInformation) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSInformation receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSInformation).MarshalBER, (*SSInformation).marshalBER, 3)

}
func (v *SSInformation) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SSInformation) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SSInformationChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInformation: forwardingInfo is nil", ber.ErrInvalidValue)
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
	case SSInformationChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInformation: callBarringInfo is nil", ber.ErrInvalidValue)
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
	case SSInformationChoiceCugInformation:
		if v.CugInformation == nil {
			return nil, fmt.Errorf("%w: choice SSInformation: cug-Information is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.CugInformation.MarshalBER(ber.ChildEncodeOptions(opts, "cug-Information")...)
		if err != nil {
			return nil, qualifyBERError(err, "cug-Information", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "cug-Information", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SSInformationChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("%w: choice SSInformation: ss-Data is nil", ber.ErrInvalidValue)
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
		return nil, fmt.Errorf("unknown choice %d for SSInformation", v.Choice)
	}
}

// MarshalDER encodes SSInformation to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSInformation) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSInformation receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SSInformationChoiceForwardingInfo:
		if v.ForwardingInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInformation: forwardingInfo is nil", ber.ErrInvalidValue)
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
	case SSInformationChoiceCallBarringInfo:
		if v.CallBarringInfo == nil {
			return nil, fmt.Errorf("%w: choice SSInformation: callBarringInfo is nil", ber.ErrInvalidValue)
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
	case SSInformationChoiceCugInformation:
		if v.CugInformation == nil {
			return nil, fmt.Errorf("%w: choice SSInformation: cug-Information is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.CugInformation.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cug-Information", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "cug-Information", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "cug-Information", "encoding", true)
		}
		return enc_der_2, nil
	case SSInformationChoiceSsData:
		if v.SsData == nil {
			return nil, fmt.Errorf("%w: choice SSInformation: ss-Data is nil", ber.ErrInvalidValue)
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
		case SSInformationChoiceForwardingInfo:
			return nil, qualifyBERError(err, "forwardingInfo", "encoding", true)
		case SSInformationChoiceCallBarringInfo:
			return nil, qualifyBERError(err, "callBarringInfo", "encoding", true)
		case SSInformationChoiceCugInformation:
			return nil, qualifyBERError(err, "cug-Information", "encoding", true)
		case SSInformationChoiceSsData:
			return nil, qualifyBERError(err, "ss-Data", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SSInformation as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SSInformation) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSInformation from BER/DER format.
func (destination *SSInformation) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSInformation destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSInformation)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSInformation).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SSInformation
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.SS-Information", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSInformation{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SSInformation CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SSInformation: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SSInformation CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SSInformation", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSInformation.forwardingInfo", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSInformation.callBarringInfo", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSInformation.cug-Information", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSInformation.ss-Data", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = SSInformationChoiceForwardingInfo
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
		v.Choice = SSInformationChoiceCallBarringInfo
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
		v.Choice = SSInformationChoiceCugInformation
		ber.MarkPreflightTarget(opts, "cug-Information", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "cug-Information", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec CUGInformation
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "cug-Information")...); unmErr != nil {
			return qualifyBERError(unmErr, "cug-Information", "decoding", false)
		}
		v.CugInformation = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = SSInformationChoiceSsData
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
		return fmt.Errorf("%w: unknown tag %s for SSInformation CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
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
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERSSInfoList", "37.4", "SS-InfoList", "SIZE (1..30)", len(list)); constraintErr != nil {
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
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-DataTypes.SS-InfoList", "37.4", "SS-InfoList", "SIZE (1..30)", len(list)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.SS-InfoList", opts)
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
	var result []SSInformation
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem SSInformation
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
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-DataTypes.SS-InfoList", "37.4", "SS-InfoList", "SIZE (1..30)", len(result)); constraintErr != nil {
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
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, s581f3f_9, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
	}
	children = append(children, enc_sscode...)
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := checkEncodedLength(opts, s581f3f_9, "37.4", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, s581f3f_9, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
	}
	children = append(children, enc_sscode...)
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := checkEncodedLength(nil, s581f3f_9, "37.4", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_9, opts)
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
			if constraintErr := checkDecodedLength(opts, s581f3f_9, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
				return constraintErr
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
					if constraintErr := checkDecodedLength(opts, s581f3f_9, "37.4", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) {
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
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SSData", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBERSSDataList encodes a SSDataList list to BER.
func MarshalBERSSDataList(collection *SSDataList, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSDataList, marshalBERSSDataList, 3, UnmarshalBERSSDataList)

}
func marshalBERSSDataList(collection *SSDataList, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERSSDataList", "37.4", "SS-DataList", "SIZE (1..30)", len(list)); constraintErr != nil {
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

func appendBERLinearSSDataList(encoder *ber.LinearEncoder, collection *SSDataList, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSDataList(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSDataList encodes a SSDataList list to DER.
func MarshalDERSSDataList(collection *SSDataList) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-DataTypes.SS-DataList", "37.4", "SS-DataList", "SIZE (1..30)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSDataList as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSDataList(encoder *ber.LinearEncoder, collection *SSDataList) ([]byte, error) {
	encoded, err := MarshalDERSSDataList(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSDataList decodes a SSDataList list from BER.
func UnmarshalBERSSDataList(data []byte, opts ...ber.DecodeOption) (returnValue *SSDataList, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERSSDataList(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.SS-DataList", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSDataList", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSDataList", Cause: ber.ErrExtraData}
	}
	var result []SSData
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem SSData
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
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-DataTypes.SS-DataList", "37.4", "SS-DataList", "SIZE (1..30)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSDataList{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSDataList); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
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
	case SSSubscriptionOptionChoicePerCallBasis:
		if v.PerCallBasis == nil {
			return nil, fmt.Errorf("%w: choice SSSubscriptionOption: perCallBasis is nil", ber.ErrInvalidValue)
		}
		enc_0 := ber.EncodeBoolean(*v.PerCallBasis)
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "perCallBasis", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SSSubscriptionOptionChoiceNotificationToHeldRetrievedParty:
		if v.NotificationToHeldRetrievedParty == nil {
			return nil, fmt.Errorf("%w: choice SSSubscriptionOption: notificationToHeldRetrievedParty is nil", ber.ErrInvalidValue)
		}
		enc_1 := ber.EncodeBoolean(*v.NotificationToHeldRetrievedParty)
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "notificationToHeldRetrievedParty", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SSSubscriptionOptionChoiceUserToUserServiceIndicator:
		if v.UserToUserServiceIndicator == nil {
			return nil, fmt.Errorf("%w: choice SSSubscriptionOption: userToUserServiceIndicator is nil", ber.ErrInvalidValue)
		}
		enc_2, encodeErr_enc_2 := ber.EncodeOctetString([]byte(*v.UserToUserServiceIndicator))
		if encodeErr_enc_2 != nil {
			return nil, qualifyBERError(encodeErr_enc_2, "userToUserServiceIndicator", "encoding", false)
		}
		if len(*v.UserToUserServiceIndicator) < 1 || len(*v.UserToUserServiceIndicator) > 1 {
			if constraintErr := checkEncodedLength(opts, s581f3f_10, "37.4", "userToUserServiceIndicator", "SIZE (1)", len(*v.UserToUserServiceIndicator)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "userToUserServiceIndicator", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SSSubscriptionOptionChoiceMaximumConfereesNumber:
		if v.MaximumConfereesNumber == nil {
			return nil, fmt.Errorf("%w: choice SSSubscriptionOption: maximumConfereesNumber is nil", ber.ErrInvalidValue)
		}
		enc_3 := ber.EncodeInteger(int64(*v.MaximumConfereesNumber))
		if !(int64(*v.MaximumConfereesNumber) >= 1 && int64(*v.MaximumConfereesNumber) <= 10) {
			if constraintErr := checkEncodedValue(opts, s581f3f_10, "37.3", "maximumConfereesNumber", "(1..10)", ber.ObserveInteger(int64(*v.MaximumConfereesNumber))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 8, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "maximumConfereesNumber", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	case SSSubscriptionOptionChoiceHuntGroupAccessSelectionOrder:
		if v.HuntGroupAccessSelectionOrder == nil {
			return nil, fmt.Errorf("%w: choice SSSubscriptionOption: huntGroupAccessSelectionOrder is nil", ber.ErrInvalidValue)
		}
		enc_4 := ber.EncodeEnumerated(int64(*v.HuntGroupAccessSelectionOrder))
		if int64(*v.HuntGroupAccessSelectionOrder) != 0 && int64(*v.HuntGroupAccessSelectionOrder) != 1 {
			if constraintErr := checkEncodedValue(opts, s581f3f_10, "15", "huntGroupAccessSelectionOrder", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.HuntGroupAccessSelectionOrder))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_4, tagErr_enc_4 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 9, enc_4)
		if tagErr_enc_4 != nil {
			return nil, qualifyBERError(tagErr_enc_4, "huntGroupAccessSelectionOrder", "encoding", false)
		}
		enc_4 = retagged_enc_4
		return enc_4, nil
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
		case SSSubscriptionOptionChoicePerCallBasis:
			return nil, qualifyBERError(err, "perCallBasis", "encoding", true)
		case SSSubscriptionOptionChoiceNotificationToHeldRetrievedParty:
			return nil, qualifyBERError(err, "notificationToHeldRetrievedParty", "encoding", true)
		case SSSubscriptionOptionChoiceUserToUserServiceIndicator:
			return nil, qualifyBERError(err, "userToUserServiceIndicator", "encoding", true)
		case SSSubscriptionOptionChoiceMaximumConfereesNumber:
			return nil, qualifyBERError(err, "maximumConfereesNumber", "encoding", true)
		case SSSubscriptionOptionChoiceHuntGroupAccessSelectionOrder:
			return nil, qualifyBERError(err, "huntGroupAccessSelectionOrder", "encoding", true)
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_10, opts)
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

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSSubscriptionOption.perCallBasis", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSSubscriptionOption.notificationToHeldRetrievedParty", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSSubscriptionOption.maximumConfereesNumber", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SSSubscriptionOption.huntGroupAccessSelectionOrder", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOptionChoicePerCallBasis
		ber.MarkPreflightTarget(opts, "perCallBasis", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "perCallBasis", "decoding", false)
		}
		_ = rawVal
		decVal, boolErr := ber.DecodeBooleanValue(rawVal)
		if boolErr != nil {
			return qualifyBERError(boolErr, "perCallBasis", "decoding", false)
		}
		if len(rawVal) == 1 && rawVal[0] != 0 && rawVal[0] != 0xff {
			ber.MarkBERNonCanonical(opts)
		}
		v.PerCallBasis = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOptionChoiceNotificationToHeldRetrievedParty
		ber.MarkPreflightTarget(opts, "notificationToHeldRetrievedParty", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "notificationToHeldRetrievedParty", "decoding", false)
		}
		_ = rawVal
		decVal, boolErr := ber.DecodeBooleanValue(rawVal)
		if boolErr != nil {
			return qualifyBERError(boolErr, "notificationToHeldRetrievedParty", "decoding", false)
		}
		if len(rawVal) == 1 && rawVal[0] != 0 && rawVal[0] != 0xff {
			ber.MarkBERNonCanonical(opts)
		}
		v.NotificationToHeldRetrievedParty = &decVal
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
		v.Choice = SSSubscriptionOptionChoiceUserToUserServiceIndicator
		ber.MarkPreflightTarget(opts, "userToUserServiceIndicator", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "userToUserServiceIndicator", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "userToUserServiceIndicator", "decoding", false)
		}
		tmp := UserToUserServiceIndicator(decVal)
		v.UserToUserServiceIndicator = &tmp
		if len(*v.UserToUserServiceIndicator) < 1 || len(*v.UserToUserServiceIndicator) > 1 {
			if constraintErr := checkDecodedLength(opts, s581f3f_10, "37.4", "userToUserServiceIndicator", "SIZE (1)", len(*v.UserToUserServiceIndicator)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 8 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOptionChoiceMaximumConfereesNumber
		ber.MarkPreflightTarget(opts, "maximumConfereesNumber", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "maximumConfereesNumber", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeIntegerValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "maximumConfereesNumber", "decoding", false)
		}
		tmp := MaximumConfereesNumber(decVal)
		v.MaximumConfereesNumber = &tmp
		if !(int64(*v.MaximumConfereesNumber) >= 1 && int64(*v.MaximumConfereesNumber) <= 10) {
			if constraintErr := checkDecodedValue(opts, s581f3f_10, "37.3", "maximumConfereesNumber", "(1..10)", ber.ObserveInteger(int64(*v.MaximumConfereesNumber))); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 9 && peekTag.Constructed == false {
		v.Choice = SSSubscriptionOptionChoiceHuntGroupAccessSelectionOrder
		ber.MarkPreflightTarget(opts, "huntGroupAccessSelectionOrder", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "huntGroupAccessSelectionOrder", "decoding", false)
		}
		_ = rawVal
		decVal, intErr := ber.DecodeEnumeratedValue(rawVal)
		if intErr != nil {
			return qualifyBERError(intErr, "huntGroupAccessSelectionOrder", "decoding", false)
		}
		tmp := HuntGroupAccessSelectionOrder(decVal)
		v.HuntGroupAccessSelectionOrder = &tmp
		if int64(*v.HuntGroupAccessSelectionOrder) != 0 && int64(*v.HuntGroupAccessSelectionOrder) != 1 {
			if constraintErr := checkDecodedValue(opts, s581f3f_10, "15", "huntGroupAccessSelectionOrder", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.HuntGroupAccessSelectionOrder))); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for SSSubscriptionOption CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
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
	if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
		if constraintErr := checkEncodedLength(opts, s581f3f_11, "37.4", "cug-interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(v.CugInterlock))
	if encodeErr_enc_cuginterlock != nil {
		return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-interlock", "encoding", false)
	}
	children = append(children, enc_cuginterlock...)
	if len(v.CugIndex) < 1 || len(v.CugIndex) > 1 {
		if constraintErr := checkEncodedLength(opts, s581f3f_11, "37.4", "cug-Index", "SIZE (1)", len(v.CugIndex)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cugindex, encodeErr_enc_cugindex := ber.EncodeOctetString([]byte(v.CugIndex))
	if encodeErr_enc_cugindex != nil {
		return nil, qualifyBERError(encodeErr_enc_cugindex, "cug-Index", "encoding", false)
	}
	children = append(children, enc_cugindex...)
	if len(v.CugOptions) < 1 || len(v.CugOptions) > 1 {
		if constraintErr := checkEncodedLength(opts, s581f3f_11, "37.4", "cug-Options", "SIZE (1)", len(v.CugOptions)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cugoptions, encodeErr_enc_cugoptions := ber.EncodeOctetString([]byte(v.CugOptions))
	if encodeErr_enc_cugoptions != nil {
		return nil, qualifyBERError(encodeErr_enc_cugoptions, "cug-Options", "encoding", false)
	}
	children = append(children, enc_cugoptions...)
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := checkEncodedLength(opts, s581f3f_11, "37.4", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", false)
	}
	children = append(children, enc_ssstatus...)
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
	if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
		if constraintErr := checkEncodedLength(nil, s581f3f_11, "37.4", "cug-interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(v.CugInterlock))
	if encodeErr_enc_cuginterlock != nil {
		return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-interlock", "encoding", true)
	}
	children = append(children, enc_cuginterlock...)
	if len(v.CugIndex) < 1 || len(v.CugIndex) > 1 {
		if constraintErr := checkEncodedLength(nil, s581f3f_11, "37.4", "cug-Index", "SIZE (1)", len(v.CugIndex)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cugindex, encodeErr_enc_cugindex := ber.EncodeOctetString([]byte(v.CugIndex))
	if encodeErr_enc_cugindex != nil {
		return nil, qualifyBERError(encodeErr_enc_cugindex, "cug-Index", "encoding", true)
	}
	children = append(children, enc_cugindex...)
	if len(v.CugOptions) < 1 || len(v.CugOptions) > 1 {
		if constraintErr := checkEncodedLength(nil, s581f3f_11, "37.4", "cug-Options", "SIZE (1)", len(v.CugOptions)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cugoptions, encodeErr_enc_cugoptions := ber.EncodeOctetString([]byte(v.CugOptions))
	if encodeErr_enc_cugoptions != nil {
		return nil, qualifyBERError(encodeErr_enc_cugoptions, "cug-Options", "encoding", true)
	}
	children = append(children, enc_cugoptions...)
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := checkEncodedLength(nil, s581f3f_11, "37.4", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", true)
	}
	children = append(children, enc_ssstatus...)
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_11, opts)
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
	// Decode cug-interlock
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cug-interlock", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cug-interlock", content[offset:])
		val_cuginterlock, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cug-interlock", "decoding", false)
		}
		v.CugInterlock = CUGInterlock(val_cuginterlock)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.CugInterlock) < 4 || len(v.CugInterlock) > 4 {
			if constraintErr := checkDecodedLength(opts, s581f3f_11, "37.4", "cug-interlock", "SIZE (4)", len(v.CugInterlock)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cug-Index
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cug-Index", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cug-Index", content[offset:])
		val_cugindex, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cug-Index", "decoding", false)
		}
		v.CugIndex = CUGIndex(val_cugindex)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.CugIndex) < 1 || len(v.CugIndex) > 1 {
			if constraintErr := checkDecodedLength(opts, s581f3f_11, "37.4", "cug-Index", "SIZE (1)", len(v.CugIndex)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cug-Options
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cug-Options", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cug-Options", content[offset:])
		val_cugoptions, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cug-Options", "decoding", false)
		}
		v.CugOptions = CUGOptions(val_cugoptions)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.CugOptions) < 1 || len(v.CugOptions) > 1 {
			if constraintErr := checkDecodedLength(opts, s581f3f_11, "37.4", "cug-Options", "SIZE (1)", len(v.CugOptions)); constraintErr != nil {
				return constraintErr
			}
		}
	}
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
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
			if constraintErr := checkDecodedLength(opts, s581f3f_11, "37.4", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CUGFeature", Cause: ber.ErrUnexpectedElement}
	}
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
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERCUGFeatureList", "37.4", "CUG-FeatureList", "SIZE (1..10)", len(list)); constraintErr != nil {
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
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-DataTypes.CUG-FeatureList", "37.4", "CUG-FeatureList", "SIZE (1..10)", len(list)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.CUG-FeatureList", opts)
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
	if len(result) < 1 || len(result) > 10 {
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-DataTypes.CUG-FeatureList", "37.4", "CUG-FeatureList", "SIZE (1..10)", len(result)); constraintErr != nil {
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

// MarshalBER encodes CUGInformation to BER format.
func (v *CUGInformation) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CUGInformation receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CUGInformation).MarshalBER, (*CUGInformation).marshalBER, 3)

}
func (v *CUGInformation) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.CugFacilities) < 1 || len(v.CugFacilities) > 1 {
		if constraintErr := checkEncodedLength(opts, s581f3f_12, "37.4", "cug-Facilities", "SIZE (1)", len(v.CugFacilities)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cugfacilities, encodeErr_enc_cugfacilities := ber.EncodeOctetString([]byte(v.CugFacilities))
	if encodeErr_enc_cugfacilities != nil {
		return nil, qualifyBERError(encodeErr_enc_cugfacilities, "cug-Facilities", "encoding", false)
	}
	children = append(children, enc_cugfacilities...)
	enc_component1, err := v.Component1.MarshalBER(ber.ChildEncodeOptions(opts, "component1")...)
	if err != nil {
		return nil, qualifyBERError(err, "component1", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_component1)
	children = append(children, enc_component1...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CUGInformation) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CUGInformation to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CUGInformation) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CUGInformation receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.CugFacilities) < 1 || len(v.CugFacilities) > 1 {
		if constraintErr := checkEncodedLength(nil, s581f3f_12, "37.4", "cug-Facilities", "SIZE (1)", len(v.CugFacilities)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cugfacilities, encodeErr_enc_cugfacilities := ber.EncodeOctetString([]byte(v.CugFacilities))
	if encodeErr_enc_cugfacilities != nil {
		return nil, qualifyBERError(encodeErr_enc_cugfacilities, "cug-Facilities", "encoding", true)
	}
	children = append(children, enc_cugfacilities...)
	enc_component1, err := v.Component1.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "component1", "encoding", true)
	}
	children = append(children, enc_component1...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding CUGInformation as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CUGInformation) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CUGInformation from BER/DER format.
func (destination *CUGInformation) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CUGInformation destination is nil", ber.ErrInvalidValue)
	}
	v := new(CUGInformation)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CUGInformation
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_12, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CUGInformation{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CUGInformation).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CUGInformation SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGInformation", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cug-Facilities
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cug-Facilities", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cug-Facilities", content[offset:])
		val_cugfacilities, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cug-Facilities", "decoding", false)
		}
		v.CugFacilities = CUGFacilities(val_cugfacilities)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.CugFacilities) < 1 || len(v.CugFacilities) > 1 {
			if constraintErr := checkDecodedLength(opts, s581f3f_12, "37.4", "cug-Facilities", "SIZE (1)", len(v.CugFacilities)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode component1
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field component1", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "component1", content[offset:])
		// Decode nested CHOICE (CUGInformationComponent1)
		_, n_component1, _, tlvErr_component1 := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_component1 != nil {
			return qualifyBERError(tlvErr_component1, "component1", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_component1 < 0 || n_component1 > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Component1.UnmarshalBER(content[offset:offset+n_component1], ber.ChildDecodeOptions(opts, "component1")...); unmErr != nil {
			return qualifyBERError(unmErr, "component1", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_component1 < 0 || n_component1 > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_component1
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CUGInformation", Cause: ber.ErrUnexpectedElement}
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
			if constraintErr := checkEncodedLength(opts, s581f3f_13, "37.4", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(opts, s581f3f_13, "37.4", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_forwardingfeaturelist, err := MarshalBERForwardingFeatureList(v.ForwardingFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "forwardingFeatureList"))...)
	if err != nil {
		return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_forwardingfeaturelist)
	children = append(children, enc_forwardingfeaturelist...)
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
			if constraintErr := checkEncodedLength(nil, s581f3f_13, "37.4", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
		if constraintErr := checkEncodedLength(nil, s581f3f_13, "37.4", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_forwardingfeaturelist, err := MarshalDERForwardingFeatureList(v.ForwardingFeatureList)
	if err != nil {
		return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", true)
	}
	children = append(children, enc_forwardingfeaturelist...)
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_13, opts)
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
					if constraintErr := checkDecodedLength(opts, s581f3f_13, "37.4", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
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
			if constraintErr := checkDecodedLength(opts, s581f3f_13, "37.4", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ForwardingInfo", Cause: ber.ErrUnexpectedElement}
	}
	return nil
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
	if len(v.ForwardedToNumber) < 1 || len(v.ForwardedToNumber) > 10 {
		if constraintErr := checkEncodedLength(opts, s581f3f_14, "37.4", "forwardedToNumber", "SIZE (1..10)", len(v.ForwardedToNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.ForwardedToNumber) < 1 || len(v.ForwardedToNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, s581f3f_14, "37.4", "forwardedToNumber", "SIZE (1..20)", len(v.ForwardedToNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(v.ForwardedToNumber))
	if encodeErr_enc_forwardedtonumber != nil {
		return nil, qualifyBERError(encodeErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", false)
	}
	retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
	if tagErr_enc_forwardedtonumber != nil {
		return nil, qualifyBERError(tagErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", false)
	}
	enc_forwardedtonumber = retagged_enc_forwardedtonumber
	children = append(children, enc_forwardedtonumber...)
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := checkEncodedLength(opts, s581f3f_14, "37.4", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
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
	if len(v.ForwardedToNumber) < 1 || len(v.ForwardedToNumber) > 10 {
		if constraintErr := checkEncodedLength(nil, s581f3f_14, "37.4", "forwardedToNumber", "SIZE (1..10)", len(v.ForwardedToNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.ForwardedToNumber) < 1 || len(v.ForwardedToNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, s581f3f_14, "37.4", "forwardedToNumber", "SIZE (1..20)", len(v.ForwardedToNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_forwardedtonumber, encodeErr_enc_forwardedtonumber := ber.EncodeOctetString([]byte(v.ForwardedToNumber))
	if encodeErr_enc_forwardedtonumber != nil {
		return nil, qualifyBERError(encodeErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", true)
	}
	retagged_enc_forwardedtonumber, tagErr_enc_forwardedtonumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_forwardedtonumber)
	if tagErr_enc_forwardedtonumber != nil {
		return nil, qualifyBERError(tagErr_enc_forwardedtonumber, "forwardedToNumber", "encoding", true)
	}
	enc_forwardedtonumber = retagged_enc_forwardedtonumber
	children = append(children, enc_forwardedtonumber...)
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := checkEncodedLength(nil, s581f3f_14, "37.4", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_14, opts)
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
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field forwardedToNumber", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 5 {
			return fmt.Errorf("%w: expected tag [%s %d] for forwardedToNumber, got %s", ber.ErrUnexpectedElement, "CONTEXT", 5, reqTag_)
		}
	}
	{
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
		v.ForwardedToNumber = IsdnAddressString(decVal_forwardedtonumber)
		if offset > len(content) || n_forwardedtonumber < 0 || n_forwardedtonumber > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_forwardedtonumber
		if len(v.ForwardedToNumber) < 1 || len(v.ForwardedToNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, s581f3f_14, "37.4", "forwardedToNumber", "SIZE (1..10)", len(v.ForwardedToNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.ForwardedToNumber) < 1 || len(v.ForwardedToNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s581f3f_14, "37.4", "forwardedToNumber", "SIZE (1..20)", len(v.ForwardedToNumber)); constraintErr != nil {
				return constraintErr
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
					if constraintErr := checkDecodedLength(opts, s581f3f_14, "37.4", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ForwardingData", Cause: ber.ErrUnexpectedElement}
	}
	return nil
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
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := checkEncodedLength(opts, s581f3f_15, "37.4", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", false)
	}
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", false)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, s581f3f_15, "37.4", "forwardedToNumber", "SIZE (1..10)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s581f3f_15, "37.4", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := checkEncodedLength(opts, s581f3f_15, "37.4", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
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
			if constraintErr := checkEncodedValue(opts, s581f3f_15, "37.3", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := checkEncodedLength(nil, s581f3f_15, "37.4", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", true)
	}
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", true)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
	if v.ForwardedToNumber != nil {
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 10 {
			if constraintErr := checkEncodedLength(nil, s581f3f_15, "37.4", "forwardedToNumber", "SIZE (1..10)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, s581f3f_15, "37.4", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
	if v.ForwardingOptions != nil {
		if len(*v.ForwardingOptions) < 1 || len(*v.ForwardingOptions) > 1 {
			if constraintErr := checkEncodedLength(nil, s581f3f_15, "37.4", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
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
			if constraintErr := checkEncodedValue(nil, s581f3f_15, "37.3", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_15, opts)
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
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field ss-Status", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("%w: expected tag [%s %d] for ss-Status, got %s", ber.ErrUnexpectedElement, "CONTEXT", 4, reqTag_)
		}
	}
	{
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
		v.SsStatus = SSStatus(decVal_ssstatus)
		if offset < 0 || offset >
			len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_ssstatus
		if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
			if constraintErr := checkDecodedLength(opts, s581f3f_15, "37.4", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
				return constraintErr
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
				tmp_forwardedtonumber := IsdnAddressString(decVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				if offset < 0 || offset >
					len(content) || n_forwardedtonumber < 0 || n_forwardedtonumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtonumber
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 10 {
					if constraintErr := checkDecodedLength(opts, s581f3f_15, "37.4", "forwardedToNumber", "SIZE (1..10)", len(*v.ForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, s581f3f_15, "37.4", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
					if constraintErr := checkDecodedLength(opts, s581f3f_15, "37.4", "forwardingOptions", "SIZE (1)", len(*v.ForwardingOptions)); constraintErr != nil {
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
					if constraintErr := checkDecodedValue(opts, s581f3f_15, "37.3", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ForwardingFeature", Cause: ber.ErrUnexpectedElement}
	}
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
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERForwardingFeatureList", "37.4", "ForwardingFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-DataTypes.ForwardingFeatureList", "37.4", "ForwardingFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.ForwardingFeatureList", opts)
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
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-DataTypes.ForwardingFeatureList", "37.4", "ForwardingFeatureList", "SIZE (1..13)", len(result)); constraintErr != nil {
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
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, s581f3f_16, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
	}
	children = append(children, enc_sscode...)
	if v.CallBarringFeatureList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "callBarringFeatureList", "encoding", false)
	}
	if len((v.CallBarringFeatureList).Values) < 1 || len((v.CallBarringFeatureList).Values) > 13 {
		if constraintErr := checkEncodedLength(opts, s581f3f_16, "37.4", "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callbarringfeaturelist, err := MarshalBERCallBarringFeatureList(v.CallBarringFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "callBarringFeatureList"))...)
	if err != nil {
		return nil, qualifyBERError(err, "callBarringFeatureList", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_callbarringfeaturelist)
	children = append(children, enc_callbarringfeaturelist...)
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
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, s581f3f_16, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
	}
	children = append(children, enc_sscode...)
	if v.CallBarringFeatureList == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "callBarringFeatureList", "encoding", true)
	}
	if len((v.CallBarringFeatureList).Values) < 1 || len((v.CallBarringFeatureList).Values) > 13 {
		if constraintErr := checkEncodedLength(nil, s581f3f_16, "37.4", "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callbarringfeaturelist, err := MarshalDERCallBarringFeatureList(v.CallBarringFeatureList)
	if err != nil {
		return nil, qualifyBERError(err, "callBarringFeatureList", "encoding", true)
	}
	children = append(children, enc_callbarringfeaturelist...)
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_16, opts)
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
			if constraintErr := checkDecodedLength(opts, s581f3f_16, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
				return constraintErr
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
			if constraintErr := checkDecodedLength(opts, s581f3f_16, "37.4", "callBarringFeatureList", "SIZE (1..13)", len((v.CallBarringFeatureList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CallBarringInfo", Cause: ber.ErrUnexpectedElement}
	}
	return nil
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
	if v.BasicServiceCode != nil {
		enc_basicservicecode, err := v.BasicServiceCode.MarshalBER(ber.ChildEncodeOptions(opts, "basicServiceCode")...)
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceCode", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservicecode)
		children = append(children, enc_basicservicecode...)
	}
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := checkEncodedLength(opts, s581f3f_17, "37.4", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", false)
	}
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", false)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
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
	if v.BasicServiceCode != nil {
		enc_basicservicecode, err := v.BasicServiceCode.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "basicServiceCode", "encoding", true)
		}
		children = append(children, enc_basicservicecode...)
	}
	if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
		if constraintErr := checkEncodedLength(nil, s581f3f_17, "37.4", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssstatus, encodeErr_enc_ssstatus := ber.EncodeOctetString([]byte(v.SsStatus))
	if encodeErr_enc_ssstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_ssstatus, "ss-Status", "encoding", true)
	}
	retagged_enc_ssstatus, tagErr_enc_ssstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_ssstatus)
	if tagErr_enc_ssstatus != nil {
		return nil, qualifyBERError(tagErr_enc_ssstatus, "ss-Status", "encoding", true)
	}
	enc_ssstatus = retagged_enc_ssstatus
	children = append(children, enc_ssstatus...)
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_17, opts)
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
	// Decode basicServiceCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) || (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) {
				ber.MarkPreflightTarget(opts, "basicServiceCode", content[offset:])
				// Decode nested CHOICE (BasicServiceCode)
				_, n_basicservicecode, _, tlvErr_basicservicecode := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_basicservicecode != nil {
					return qualifyBERError(tlvErr_basicservicecode, "basicServiceCode", "decoding", false)
				}
				var dec_basicservicecode BasicServiceCode
				if offset > len(content) || n_basicservicecode < 0 || n_basicservicecode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservicecode.UnmarshalBER(content[offset:offset+n_basicservicecode], ber.ChildDecodeOptions(opts, "basicServiceCode")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicServiceCode", "decoding", false)
				}
				v.BasicServiceCode = &dec_basicservicecode
				if offset > len(content) || n_basicservicecode < 0 || n_basicservicecode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservicecode
			}
		}
	}
	// Decode ss-Status
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field ss-Status", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 4 {
			return fmt.Errorf("%w: expected tag [%s %d] for ss-Status, got %s", ber.ErrUnexpectedElement, "CONTEXT", 4, reqTag_)
		}
	}
	{
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
		v.SsStatus = SSStatus(decVal_ssstatus)
		if offset < 0 || offset >
			len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_ssstatus
		if len(v.SsStatus) < 1 || len(v.SsStatus) > 1 {
			if constraintErr := checkDecodedLength(opts, s581f3f_17, "37.4", "ss-Status", "SIZE (1)", len(v.SsStatus)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CallBarringFeature", Cause: ber.ErrUnexpectedElement}
	}
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
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERCallBarringFeatureList", "37.4", "CallBarringFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-DataTypes.CallBarringFeatureList", "37.4", "CallBarringFeatureList", "SIZE (1..13)", len(list)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.CallBarringFeatureList", opts)
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
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-DataTypes.CallBarringFeatureList", "37.4", "CallBarringFeatureList", "SIZE (1..13)", len(result)); constraintErr != nil {
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

// MarshalBER encodes SubscriberData to BER format.
func (v *SubscriberData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SubscriberData).MarshalBER, (*SubscriberData).marshalBER, 3)

}
func (v *SubscriberData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkEncodedLength(opts, s581f3f_18, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkEncodedLength(opts, s581f3f_18, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.MsIsdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", false)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msIsdn", "encoding", false)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := checkEncodedLength(opts, s581f3f_18, "37.4", "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, qualifyBERError(encodeErr_enc_category, "category", "encoding", false)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_category)
		if tagErr_enc_category != nil {
			return nil, qualifyBERError(tagErr_enc_category, "category", "encoding", false)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.SubscriberStatus != nil {
		if int64(*v.SubscriberStatus) != 0 && int64(*v.SubscriberStatus) != 1 {
			if constraintErr := checkEncodedValue(opts, s581f3f_18, "15", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_subscriberstatus := ber.EncodeEnumerated(int64(*v.SubscriberStatus))
		retagged_enc_subscriberstatus, tagErr_enc_subscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_subscriberstatus)
		if tagErr_enc_subscriberstatus != nil {
			return nil, qualifyBERError(tagErr_enc_subscriberstatus, "subscriberStatus", "encoding", false)
		}
		enc_subscriberstatus = retagged_enc_subscriberstatus
		children = append(children, enc_subscriberstatus...)
	}
	if v.BearerServiceList != nil {
		if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
			if constraintErr := checkEncodedLength(opts, s581f3f_18, "37.4", "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservicelist, err := MarshalBERBearerServiceList(v.BearerServiceList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "bearerServiceList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "bearerServiceList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berBearerServiceListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_bearerservicelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_bearerservicelist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 4}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "bearerServiceList", "encoding", false)
				}
			}
		} else {
			retagged_enc_bearerservicelist, tagErr_enc_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_bearerservicelist)
			if tagErr_enc_bearerservicelist != nil {
				return nil, qualifyBERError(tagErr_enc_bearerservicelist, "bearerServiceList", "encoding", false)
			}
			enc_bearerservicelist = retagged_enc_bearerservicelist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_bearerservicelist)
		children = append(children, enc_bearerservicelist...)
	}
	if v.TeleserviceList != nil {
		if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
			if constraintErr := checkEncodedLength(opts, s581f3f_18, "37.4", "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicelist, err := MarshalBERTeleserviceList(v.TeleserviceList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "teleserviceList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "teleserviceList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berTeleserviceListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_teleservicelist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_teleservicelist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 6}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "teleserviceList", "encoding", false)
				}
			}
		} else {
			retagged_enc_teleservicelist, tagErr_enc_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_teleservicelist)
			if tagErr_enc_teleservicelist != nil {
				return nil, qualifyBERError(tagErr_enc_teleservicelist, "teleserviceList", "encoding", false)
			}
			enc_teleservicelist = retagged_enc_teleservicelist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_teleservicelist)
		children = append(children, enc_teleservicelist...)
	}
	if v.ProvisonedSupplServices != nil {
		if len((v.ProvisonedSupplServices).Values) < 1 || len((v.ProvisonedSupplServices).Values) > 30 {
			if constraintErr := checkEncodedLength(opts, s581f3f_18, "37.4", "provisonedSupplServices", "SIZE (1..30)", len((v.ProvisonedSupplServices).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_provisonedsupplservices, err := MarshalBERSSInfoList(v.ProvisonedSupplServices, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "provisonedSupplServices"))...)
		if err != nil {
			return nil, qualifyBERError(err, "provisonedSupplServices", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berProvisonedSupplServicesIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_provisonedsupplservices)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_provisonedsupplservices, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 7}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "provisonedSupplServices", "encoding", false)
				}
			}
		} else {
			retagged_enc_provisonedsupplservices, tagErr_enc_provisonedsupplservices := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_provisonedsupplservices)
			if tagErr_enc_provisonedsupplservices != nil {
				return nil, qualifyBERError(tagErr_enc_provisonedsupplservices, "provisonedSupplServices", "encoding", false)
			}
			enc_provisonedsupplservices = retagged_enc_provisonedsupplservices
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_provisonedsupplservices)
		children = append(children, enc_provisonedsupplservices...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SubscriberData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SubscriberData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SubscriberData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SubscriberData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkEncodedLength(nil, s581f3f_18, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkEncodedLength(nil, s581f3f_18, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.MsIsdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", true)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msIsdn", "encoding", true)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := checkEncodedLength(nil, s581f3f_18, "37.4", "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, qualifyBERError(encodeErr_enc_category, "category", "encoding", true)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_category)
		if tagErr_enc_category != nil {
			return nil, qualifyBERError(tagErr_enc_category, "category", "encoding", true)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.SubscriberStatus != nil {
		if int64(*v.SubscriberStatus) != 0 && int64(*v.SubscriberStatus) != 1 {
			if constraintErr := checkEncodedValue(nil, s581f3f_18, "15", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_subscriberstatus := ber.EncodeEnumerated(int64(*v.SubscriberStatus))
		retagged_enc_subscriberstatus, tagErr_enc_subscriberstatus := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_subscriberstatus)
		if tagErr_enc_subscriberstatus != nil {
			return nil, qualifyBERError(tagErr_enc_subscriberstatus, "subscriberStatus", "encoding", true)
		}
		enc_subscriberstatus = retagged_enc_subscriberstatus
		children = append(children, enc_subscriberstatus...)
	}
	if v.BearerServiceList != nil {
		if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
			if constraintErr := checkEncodedLength(nil, s581f3f_18, "37.4", "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservicelist, err := MarshalDERBearerServiceList(v.BearerServiceList)
		if err != nil {
			return nil, qualifyBERError(err, "bearerServiceList", "encoding", true)
		}
		retagged_enc_bearerservicelist, tagErr_enc_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_bearerservicelist)
		if tagErr_enc_bearerservicelist != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservicelist, "bearerServiceList", "encoding", true)
		}
		enc_bearerservicelist = retagged_enc_bearerservicelist
		children = append(children, enc_bearerservicelist...)
	}
	if v.TeleserviceList != nil {
		if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
			if constraintErr := checkEncodedLength(nil, s581f3f_18, "37.4", "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicelist, err := MarshalDERTeleserviceList(v.TeleserviceList)
		if err != nil {
			return nil, qualifyBERError(err, "teleserviceList", "encoding", true)
		}
		retagged_enc_teleservicelist, tagErr_enc_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_teleservicelist)
		if tagErr_enc_teleservicelist != nil {
			return nil, qualifyBERError(tagErr_enc_teleservicelist, "teleserviceList", "encoding", true)
		}
		enc_teleservicelist = retagged_enc_teleservicelist
		children = append(children, enc_teleservicelist...)
	}
	if v.ProvisonedSupplServices != nil {
		if len((v.ProvisonedSupplServices).Values) < 1 || len((v.ProvisonedSupplServices).Values) > 30 {
			if constraintErr := checkEncodedLength(nil, s581f3f_18, "37.4", "provisonedSupplServices", "SIZE (1..30)", len((v.ProvisonedSupplServices).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_provisonedsupplservices, err := MarshalDERSSInfoList(v.ProvisonedSupplServices)
		if err != nil {
			return nil, qualifyBERError(err, "provisonedSupplServices", "encoding", true)
		}
		retagged_enc_provisonedsupplservices, tagErr_enc_provisonedsupplservices := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_provisonedsupplservices)
		if tagErr_enc_provisonedsupplservices != nil {
			return nil, qualifyBERError(tagErr_enc_provisonedsupplservices, "provisonedSupplServices", "encoding", true)
		}
		enc_provisonedsupplservices = retagged_enc_provisonedsupplservices
		children = append(children, enc_provisonedsupplservices...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SubscriberData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SubscriberData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SubscriberData from BER/DER format.
func (destination *SubscriberData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SubscriberData destination is nil", ber.ErrInvalidValue)
	}
	v := new(SubscriberData)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SubscriberData
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_18, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SubscriberData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SubscriberData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SubscriberData SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SubscriberData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msIsdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "msIsdn", content[offset:])
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msIsdn", "decoding", false)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_msisdn), "msIsdn", "decoding", false)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msIsdn", "decoding", false)
				}
				tmp_msisdn := IsdnAddressString(decVal_msisdn)
				v.MsIsdn = &tmp_msisdn
				if offset > len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
					if constraintErr := checkDecodedLength(opts, s581f3f_18, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
					if constraintErr := checkDecodedLength(opts, s581f3f_18, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode category
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "category", content[offset:])
				decodedTag_category, n_category, rawVal_category, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "category", "decoding", false)
				}
				if decodedTag_category.Class != tag.ClassContextSpecific || decodedTag_category.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_category), "category", "decoding", false)
				}
				decVal_category, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_category.Constructed, rawVal_category, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "category", "decoding", false)
				}
				tmp_category := Category(decVal_category)
				v.Category = &tmp_category
				if offset < 0 || offset >
					len(content) || n_category < 0 || n_category > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_category
				if len(*v.Category) < 1 || len(*v.Category) > 1 {
					if constraintErr := checkDecodedLength(opts, s581f3f_18, "37.4", "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode subscriberStatus
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "subscriberStatus", content[offset:])
				decodedTag_subscriberstatus, n_subscriberstatus, rawVal_subscriberstatus, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "subscriberStatus", "decoding", false)
				}
				if decodedTag_subscriberstatus.Class != tag.ClassContextSpecific || decodedTag_subscriberstatus.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_subscriberstatus), "subscriberStatus", "decoding", false)
				}
				if decodedTag_subscriberstatus.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_subscriberstatus), "subscriberStatus", "decoding", false)
				}
				decVal_subscriberstatus, intErr := ber.DecodeEnumeratedValue(rawVal_subscriberstatus)
				if intErr != nil {
					return qualifyBERError(intErr, "subscriberStatus", "decoding", false)
				}
				tmp_subscriberstatus := SubscriberStatus(decVal_subscriberstatus)
				v.SubscriberStatus = &tmp_subscriberstatus
				if offset < 0 || offset >
					len(content) || n_subscriberstatus < 0 || n_subscriberstatus >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_subscriberstatus
				if int64(*v.SubscriberStatus) != 0 && int64(*v.SubscriberStatus) != 1 {
					if constraintErr := checkDecodedValue(opts, s581f3f_18, "15", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode bearerServiceList
	v.berBearerServiceListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "bearerServiceList", content[offset:])
				decodedTag_bearerservicelist, n_bearerservicelist, rawVal_bearerservicelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bearerServiceList", "decoding", false)
				}
				if decodedTag_bearerservicelist.Class != tag.ClassContextSpecific || decodedTag_bearerservicelist.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_bearerservicelist), "bearerServiceList", "decoding", false)
				}
				if decodedTag_bearerservicelist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_bearerservicelist), "bearerServiceList", "decoding", false)
				}
				_ = rawVal_bearerservicelist
				if offset < 0 || offset >
					len(content) || n_bearerservicelist < 0 || n_bearerservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_bearerservicelist, reconstructionErr_bearerservicelist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_bearerservicelist])
				if reconstructionErr_bearerservicelist != nil {
					return qualifyBERError(reconstructionErr_bearerservicelist, "bearerServiceList", "decoding", false)
				}
				dec_bearerservicelist, unmErr := UnmarshalBERBearerServiceList(reconstructed_bearerservicelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "bearerServiceList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "bearerServiceList", "decoding", false)
				}
				v.BearerServiceList = dec_bearerservicelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berBearerServiceListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_bearerservicelist < 0 || n_bearerservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bearerservicelist
				if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
					if constraintErr := checkDecodedLength(opts, s581f3f_18, "37.4", "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode teleserviceList
	v.berTeleserviceListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "teleserviceList", content[offset:])
				decodedTag_teleservicelist, n_teleservicelist, rawVal_teleservicelist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "teleserviceList", "decoding", false)
				}
				if decodedTag_teleservicelist.Class != tag.ClassContextSpecific || decodedTag_teleservicelist.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_teleservicelist), "teleserviceList", "decoding", false)
				}
				if decodedTag_teleservicelist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_teleservicelist), "teleserviceList", "decoding", false)
				}
				_ = rawVal_teleservicelist
				if offset < 0 || offset >
					len(content) || n_teleservicelist < 0 || n_teleservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_teleservicelist, reconstructionErr_teleservicelist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_teleservicelist])
				if reconstructionErr_teleservicelist != nil {
					return qualifyBERError(reconstructionErr_teleservicelist, "teleserviceList", "decoding", false)
				}
				dec_teleservicelist, unmErr := UnmarshalBERTeleserviceList(reconstructed_teleservicelist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "teleserviceList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "teleserviceList", "decoding", false)
				}
				v.TeleserviceList = dec_teleservicelist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berTeleserviceListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_teleservicelist < 0 || n_teleservicelist >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_teleservicelist
				if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
					if constraintErr := checkDecodedLength(opts, s581f3f_18, "37.4", "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode provisonedSupplServices
	v.berProvisonedSupplServicesIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "provisonedSupplServices", content[offset:])
				decodedTag_provisonedsupplservices, n_provisonedsupplservices, rawVal_provisonedsupplservices, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "provisonedSupplServices", "decoding", false)
				}
				if decodedTag_provisonedsupplservices.Class != tag.ClassContextSpecific || decodedTag_provisonedsupplservices.Number != 7 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_provisonedsupplservices), "provisonedSupplServices", "decoding", false)
				}
				if decodedTag_provisonedsupplservices.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_provisonedsupplservices), "provisonedSupplServices", "decoding", false)
				}
				_ = rawVal_provisonedsupplservices
				if offset < 0 || offset >
					len(content) || n_provisonedsupplservices < 0 || n_provisonedsupplservices >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_provisonedsupplservices, reconstructionErr_provisonedsupplservices := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_provisonedsupplservices])
				if reconstructionErr_provisonedsupplservices != nil {
					return qualifyBERError(reconstructionErr_provisonedsupplservices, "provisonedSupplServices", "decoding", false)
				}
				dec_provisonedsupplservices, unmErr := UnmarshalBERSSInfoList(reconstructed_provisonedsupplservices, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "provisonedSupplServices"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "provisonedSupplServices", "decoding", false)
				}
				v.ProvisonedSupplServices = dec_provisonedsupplservices
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berProvisonedSupplServicesIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_provisonedsupplservices < 0 || n_provisonedsupplservices >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_provisonedsupplservices
				if len((v.ProvisonedSupplServices).Values) < 1 || len((v.ProvisonedSupplServices).Values) > 30 {
					if constraintErr := checkDecodedLength(opts, s581f3f_18, "37.4", "provisonedSupplServices", "SIZE (1..30)", len((v.ProvisonedSupplServices).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SubscriberData", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes Password to BER format.
func (v *Password) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: Password receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*Password).MarshalBER, (*Password).marshalBER, 3)

}
func (v *Password) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *Password) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case PasswordChoiceAlternative0:
		if v.Alternative0 == nil {
			return nil, fmt.Errorf("%w: choice Password: alternative0 is nil", ber.ErrInvalidValue)
		}
		enc_0, stringErr := ber.EncodeTLV(tag.Tag{Number: 19}, []byte(*v.Alternative0))
		if stringErr != nil {
			return nil, qualifyBERError(stringErr, "alternative0", "encoding", false)
		}
		for _, character := range []byte(*v.Alternative0) {
			if !((character >= ' ' && character <= ' ') || (character >= '\'' && character <= ')') || (character >= '+' && character <= ':') || (character >= '=' && character <= '=') || (character >= '?' && character <= '?') || (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')) {
				if constraintErr := checkEncodedValue(opts, s581f3f_19, "31, Tables 4–6", "alternative0", "PrintableString character repertoire (X.208 (11/1988) §31, Tables 4–6)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return nil, constraintErr
				}
				break
			}
		}
		if len(*v.Alternative0) < 4 || len(*v.Alternative0) > 8 {
			if constraintErr := checkEncodedLength(opts, s581f3f_19, "37.4", "alternative0", "SIZE (4..8)", len(*v.Alternative0)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case PasswordChoiceAlternative1:
		if v.Alternative1 == nil {
			return nil, fmt.Errorf("%w: choice Password: alternative1 is nil", ber.ErrInvalidValue)
		}
		enc_1, stringErr := ber.EncodeTLV(tag.Tag{Number: 18}, []byte(*v.Alternative1))
		if stringErr != nil {
			return nil, qualifyBERError(stringErr, "alternative1", "encoding", false)
		}
		if !(func() bool {
			operandErr := func() error {
				opts := []ber.DecodeOption(nil)
				_ = opts
				for _, character := range []byte(*v.Alternative1) {
					if !(((character >= ' ' && character <= ' ') || (character >= '0' && character <= '9')) && (character >= '0' && character <= '9')) {
						if constraintErr := checkDecodedValue(opts, s581f3f_19, "37.5", "union operand", "FROM permitted alphabet", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
							return constraintErr
						}
						break
					}
				}
				return nil
			}()
			return operandErr == nil
		}() || func() bool {
			operandErr := func() error {
				opts := []ber.DecodeOption(nil)
				_ = opts
				for _, character := range []byte(*v.Alternative1) {
					if !((character >= ' ' && character <= ' ') || (character >= '0' && character <= '9')) {
						if constraintErr := checkDecodedValue(opts, s581f3f_19, "31, Tables 4–6", "union operand", "NumericString character repertoire (X.208 (11/1988) §31, Tables 4–6)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
							return constraintErr
						}
						break
					}
				}
				if len(*v.Alternative1) < 4 || len(*v.Alternative1) > 4 {
					if constraintErr := checkDecodedLength(opts, s581f3f_19, "37.4", "union operand", "SIZE (4)", len(*v.Alternative1)); constraintErr != nil {
						return constraintErr
					}
				}
				return nil
			}()
			return operandErr == nil
		}()) {
			if constraintErr := checkEncodedValue(opts, s581f3f_19, "36", "alternative1", "X.208 (11/1988) §36.7 SIZE/FROM union", string(*v.Alternative1)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		for _, character := range []byte(*v.Alternative1) {
			if !((character >= ' ' && character <= ' ') || (character >= '0' && character <= '9')) {
				if constraintErr := checkEncodedValue(opts, s581f3f_19, "31, Tables 4–6", "alternative1", "NumericString character repertoire (X.208 (11/1988) §31, Tables 4–6)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return nil, constraintErr
				}
				break
			}
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for Password", v.Choice)
	}
}

// MarshalDER encodes Password to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *Password) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: Password receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case PasswordChoiceAlternative0:
			return nil, qualifyBERError(err, "alternative0", "encoding", true)
		case PasswordChoiceAlternative1:
			return nil, qualifyBERError(err, "alternative1", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding Password as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *Password) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes Password from BER/DER format.
func (destination *Password) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: Password destination is nil", ber.ErrInvalidValue)
	}
	v := new(Password)
	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*Password).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe Password
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_19, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = Password{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for Password CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for Password: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding Password CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "Password", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 19 {
		v.Choice = PasswordChoiceAlternative0
		ber.MarkPreflightTarget(opts, "alternative0", choiceData)
		decVal, _, strErr := ber.DecodeString(choiceData, 19, opts...)
		if strErr != nil {
			return qualifyBERError(strErr, "alternative0", "decoding", false)
		}
		v.Alternative0 = &decVal
		for _, character := range []byte(*v.Alternative0) {
			if !((character >= ' ' && character <= ' ') || (character >= '\'' && character <= ')') || (character >= '+' && character <= ':') || (character >= '=' && character <= '=') || (character >= '?' && character <= '?') || (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')) {
				if constraintErr := checkDecodedValue(opts, s581f3f_19, "31, Tables 4–6", "alternative0", "PrintableString character repertoire (X.208 (11/1988) §31, Tables 4–6)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return constraintErr
				}
				break
			}
		}
		if len(*v.Alternative0) < 4 || len(*v.Alternative0) > 8 {
			if constraintErr := checkDecodedLength(opts, s581f3f_19, "37.4", "alternative0", "SIZE (4..8)", len(*v.Alternative0)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 18 {
		v.Choice = PasswordChoiceAlternative1
		ber.MarkPreflightTarget(opts, "alternative1", choiceData)
		decVal, _, strErr := ber.DecodeString(choiceData, 18, opts...)
		if strErr != nil {
			return qualifyBERError(strErr, "alternative1", "decoding", false)
		}
		v.Alternative1 = &decVal
		if !(func() bool {
			operandErr := func() error {
				opts := []ber.DecodeOption(nil)
				_ = opts
				for _, character := range []byte(*v.Alternative1) {
					if !(((character >= ' ' && character <= ' ') || (character >= '0' && character <= '9')) && (character >= '0' && character <= '9')) {
						if constraintErr := checkDecodedValue(opts, s581f3f_19, "37.5", "union operand", "FROM permitted alphabet", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
							return constraintErr
						}
						break
					}
				}
				return nil
			}()
			return operandErr == nil
		}() || func() bool {
			operandErr := func() error {
				opts := []ber.DecodeOption(nil)
				_ = opts
				for _, character := range []byte(*v.Alternative1) {
					if !((character >= ' ' && character <= ' ') || (character >= '0' && character <= '9')) {
						if constraintErr := checkDecodedValue(opts, s581f3f_19, "31, Tables 4–6", "union operand", "NumericString character repertoire (X.208 (11/1988) §31, Tables 4–6)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
							return constraintErr
						}
						break
					}
				}
				if len(*v.Alternative1) < 4 || len(*v.Alternative1) > 4 {
					if constraintErr := checkDecodedLength(opts, s581f3f_19, "37.4", "union operand", "SIZE (4)", len(*v.Alternative1)); constraintErr != nil {
						return constraintErr
					}
				}
				return nil
			}()
			return operandErr == nil
		}()) {
			if constraintErr := checkDecodedValue(opts, s581f3f_19, "36", "alternative1", "X.208 (11/1988) §36.7 SIZE/FROM union", string(*v.Alternative1)); constraintErr != nil {
				return constraintErr
			}
		}
		for _, character := range []byte(*v.Alternative1) {
			if !((character >= ' ' && character <= ' ') || (character >= '0' && character <= '9')) {
				if constraintErr := checkDecodedValue(opts, s581f3f_19, "31, Tables 4–6", "alternative1", "NumericString character repertoire (X.208 (11/1988) §31, Tables 4–6)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return constraintErr
				}
				break
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for Password CHOICE", ber.ErrUnexpectedElement, peekTag)
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
	if constraintErr := checkIA5Controls(string(v.Value), opts, "SS-UserData", "MAP-DataTypes.marshalBERSSUserData"); constraintErr != nil {
		return nil, constraintErr
	}
	for _, character := range []byte(v.Value) {
		if !(character >= 0x0 && character <= 0x7f) {
			if constraintErr := checkEncodedValue(opts, "MAP-DataTypes.marshalBERSSUserData", "31, Tables 4–6", "SS-UserData", "IA5String character repertoire (X.208 (11/1988) §31, Tables 4–6)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
				return nil, constraintErr
			}
			break
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 200 {
		if constraintErr := checkEncodedLength(opts, "MAP-DataTypes.marshalBERSSUserData", "37.4", "SS-UserData", "SIZE (1..200)", len(v.Value)); constraintErr != nil {
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
	if constraintErr := checkIA5Controls(string(v.Value), nil, "SS-UserData", s581f3f_20); constraintErr != nil {
		return nil, constraintErr
	}
	for _, character := range []byte(v.Value) {
		if !(character >= 0x0 && character <= 0x7f) {
			if constraintErr := checkEncodedValue(nil, s581f3f_20, "31, Tables 4–6", "SS-UserData", "IA5String character repertoire (X.208 (11/1988) §31, Tables 4–6)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
				return nil, constraintErr
			}
			break
		}
	}
	if len(v.Value) < 1 || len(v.Value) > 200 {
		if constraintErr := checkEncodedLength(nil, s581f3f_20, "37.4", "SS-UserData", "SIZE (1..200)", len(v.Value)); constraintErr != nil {
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_20, opts)
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
				if constraintErr := checkDecodedValue(opts, s581f3f_20, "31, Tables 4–6", "SS-UserData", "IA5String character repertoire (X.208 (11/1988) §31, Tables 4–6)", fmt.Sprintf("0x%02X", character)); constraintErr != nil {
					return constraintErr
				}
				break
			}
		}
		if len(v.Value) < 1 || len(v.Value) > 200 {
			if constraintErr := checkDecodedLength(opts, s581f3f_20, "37.4", "SS-UserData", "SIZE (1..200)", len(v.Value)); constraintErr != nil {
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

// MarshalBER encodes SSChargingData to BER format.
func (v *SSChargingData) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SSChargingData receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SSChargingData).MarshalBER, (*SSChargingData).marshalBER, 3)

}
func (v *SSChargingData) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, s581f3f_21, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", false)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if int64(v.SsRequest) != 0 && int64(v.SsRequest) != 1 && int64(v.SsRequest) != 2 && int64(v.SsRequest) != 3 && int64(v.SsRequest) != 4 && int64(v.SsRequest) != 5 {
		if constraintErr := checkEncodedValue(opts, s581f3f_21, "15", "ss-Request", "ENUMERATED {0, 1, 2, 3, 4, 5}", ber.ObserveInteger(int64(v.SsRequest))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssrequest := ber.EncodeEnumerated(int64(v.SsRequest))
	retagged_enc_ssrequest, tagErr_enc_ssrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ssrequest)
	if tagErr_enc_ssrequest != nil {
		return nil, qualifyBERError(tagErr_enc_ssrequest, "ss-Request", "encoding", false)
	}
	enc_ssrequest = retagged_enc_ssrequest
	children = append(children, enc_ssrequest...)
	if v.Charge != nil {
		if !(int64(*v.Charge) >= 1 && int64(*v.Charge) <= 16777215) {
			if constraintErr := checkEncodedValue(opts, s581f3f_21, "37.3", "charge", "(1..16777215)", ber.ObserveInteger(int64(*v.Charge))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_charge := ber.EncodeInteger(int64(*v.Charge))
		retagged_enc_charge, tagErr_enc_charge := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_charge)
		if tagErr_enc_charge != nil {
			return nil, qualifyBERError(tagErr_enc_charge, "charge", "encoding", false)
		}
		enc_charge = retagged_enc_charge
		children = append(children, enc_charge...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SSChargingData) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SSChargingData to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SSChargingData) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SSChargingData receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, s581f3f_21, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(v.SsCode))
	if encodeErr_enc_sscode != nil {
		return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
	}
	retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sscode)
	if tagErr_enc_sscode != nil {
		return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", true)
	}
	enc_sscode = retagged_enc_sscode
	children = append(children, enc_sscode...)
	if int64(v.SsRequest) != 0 && int64(v.SsRequest) != 1 && int64(v.SsRequest) != 2 && int64(v.SsRequest) != 3 && int64(v.SsRequest) != 4 && int64(v.SsRequest) != 5 {
		if constraintErr := checkEncodedValue(nil, s581f3f_21, "15", "ss-Request", "ENUMERATED {0, 1, 2, 3, 4, 5}", ber.ObserveInteger(int64(v.SsRequest))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_ssrequest := ber.EncodeEnumerated(int64(v.SsRequest))
	retagged_enc_ssrequest, tagErr_enc_ssrequest := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_ssrequest)
	if tagErr_enc_ssrequest != nil {
		return nil, qualifyBERError(tagErr_enc_ssrequest, "ss-Request", "encoding", true)
	}
	enc_ssrequest = retagged_enc_ssrequest
	children = append(children, enc_ssrequest...)
	if v.Charge != nil {
		if !(int64(*v.Charge) >= 1 && int64(*v.Charge) <= 16777215) {
			if constraintErr := checkEncodedValue(nil, s581f3f_21, "37.3", "charge", "(1..16777215)", ber.ObserveInteger(int64(*v.Charge))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_charge := ber.EncodeInteger(int64(*v.Charge))
		retagged_enc_charge, tagErr_enc_charge := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_charge)
		if tagErr_enc_charge != nil {
			return nil, qualifyBERError(tagErr_enc_charge, "charge", "encoding", true)
		}
		enc_charge = retagged_enc_charge
		children = append(children, enc_charge...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SSChargingData as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SSChargingData) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SSChargingData from BER/DER format.
func (destination *SSChargingData) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SSChargingData destination is nil", ber.ErrInvalidValue)
	}
	v := new(SSChargingData)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SSChargingData
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_21, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SSChargingData{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SSChargingData).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SSChargingData SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SSChargingData", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode ss-Code
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field ss-Code", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("%w: expected tag [%s %d] for ss-Code, got %s", ber.ErrUnexpectedElement, "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
		decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Code", "decoding", false)
		}
		if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_sscode), "ss-Code", "decoding", false)
		}
		decVal_sscode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_sscode.Constructed, rawVal_sscode, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ss-Code", "decoding", false)
		}
		v.SsCode = SSCode(decVal_sscode)
		if offset > len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_sscode
		if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
			if constraintErr := checkDecodedLength(opts, s581f3f_21, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode ss-Request
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field ss-Request", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("%w: expected tag [%s %d] for ss-Request, got %s", ber.ErrUnexpectedElement, "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "ss-Request", content[offset:])
		decodedTag_ssrequest, n_ssrequest, rawVal_ssrequest, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "ss-Request", "decoding", false)
		}
		if decodedTag_ssrequest.Class != tag.ClassContextSpecific || decodedTag_ssrequest.Number != 2 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_ssrequest), "ss-Request", "decoding", false)
		}
		if decodedTag_ssrequest.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_ssrequest), "ss-Request", "decoding", false)
		}
		decVal_ssrequest, intErr := ber.DecodeEnumeratedValue(rawVal_ssrequest)
		if intErr != nil {
			return qualifyBERError(intErr, "ss-Request", "decoding", false)
		}
		v.SsRequest = SSRequest(decVal_ssrequest)
		if offset < 0 || offset >
			len(content) || n_ssrequest < 0 || n_ssrequest > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_ssrequest
		if int64(v.SsRequest) != 0 && int64(v.SsRequest) != 1 && int64(v.SsRequest) != 2 && int64(v.SsRequest) != 3 && int64(v.SsRequest) != 4 && int64(v.SsRequest) != 5 {
			if constraintErr := checkDecodedValue(opts, s581f3f_21, "15", "ss-Request", "ENUMERATED {0, 1, 2, 3, 4, 5}", ber.ObserveInteger(int64(v.SsRequest))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode charge
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "charge", content[offset:])
				decodedTag_charge, n_charge, rawVal_charge, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "charge", "decoding", false)
				}
				if decodedTag_charge.Class != tag.ClassContextSpecific || decodedTag_charge.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_charge), "charge", "decoding", false)
				}
				if decodedTag_charge.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_charge), "charge", "decoding", false)
				}
				decVal_charge, intErr := ber.DecodeIntegerValue(rawVal_charge)
				if intErr != nil {
					return qualifyBERError(intErr, "charge", "decoding", false)
				}
				tmp_charge := Charge(decVal_charge)
				v.Charge = &tmp_charge
				if offset < 0 || offset >
					len(content) || n_charge < 0 || n_charge > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_charge
				if !(int64(*v.Charge) >= 1 && int64(*v.Charge) <= 16777215) {
					if constraintErr := checkDecodedValue(opts, s581f3f_21, "37.3", "charge", "(1..16777215)", ber.ObserveInteger(int64(*v.Charge))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SSChargingData", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBERSSChargingInfo encodes a SSChargingInfo list to BER.
func MarshalBERSSChargingInfo(collection *SSChargingInfo, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSSChargingInfo, marshalBERSSChargingInfo, 3, UnmarshalBERSSChargingInfo)

}
func marshalBERSSChargingInfo(collection *SSChargingInfo, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERSSChargingInfo", "37.4", "SS-ChargingInfo", "SIZE (1..30)", len(list)); constraintErr != nil {
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

func appendBERLinearSSChargingInfo(encoder *ber.LinearEncoder, collection *SSChargingInfo, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSSChargingInfo(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSSChargingInfo encodes a SSChargingInfo list to DER.
func MarshalDERSSChargingInfo(collection *SSChargingInfo) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 30 {
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-DataTypes.SS-ChargingInfo", "37.4", "SS-ChargingInfo", "SIZE (1..30)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SSChargingInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSSChargingInfo(encoder *ber.LinearEncoder, collection *SSChargingInfo) ([]byte, error) {
	encoded, err := MarshalDERSSChargingInfo(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSSChargingInfo decodes a SSChargingInfo list from BER.
func UnmarshalBERSSChargingInfo(data []byte, opts ...ber.DecodeOption) (returnValue *SSChargingInfo, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERSSChargingInfo(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.SS-ChargingInfo", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SSChargingInfo", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SSChargingInfo", Cause: ber.ErrExtraData}
	}
	var result []SSChargingData
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem SSChargingData
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
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-DataTypes.SS-ChargingInfo", "37.4", "SS-ChargingInfo", "SIZE (1..30)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SSChargingInfo{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSSChargingInfo); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBERCallDateTime encodes a typed standalone CallDateTime, preserving unchanged received BER.
func MarshalBERCallDateTime(value *BERValue[CallDateTime], opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if value == nil {
		return nil, fmt.Errorf("%w: required CallDateTime is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(value, value.berReplayNode_, opts, MarshalBERCallDateTime, marshalBERCallDateTime, 2, UnmarshalBERCallDateTime)

}
func marshalBERCallDateTime(value *BERValue[CallDateTime], opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	v := &struct{ Value CallDateTime }{Value: value.Value}
	_ = v
	var children []byte
	if len((v.Value).String()) < 14 || len((v.Value).String()) > 24 {
		if constraintErr := checkEncodedLength(nil, "MAP-DataTypes.marshalBERCallDateTime", "37.4", "CallDateTime", "SIZE (14..24)", len((v.Value).String())); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_value, encodeErr_enc_value := encodeEditionGeneralizedTime(v.Value, "MAP-DataTypes.marshalBERCallDateTime", "CallDateTime")
	if encodeErr_enc_value != nil {
		if _, timeViolation := encodeErr_enc_value.(*ber.ValidationError); timeViolation {
			return nil, encodeErr_enc_value
		}

		return nil, fmt.Errorf("%s: %w", "encoding CallDateTime", qualifyBERError(encodeErr_enc_value, "", "encoding", false))
	}
	children = append(children, enc_value...)
	return children, nil
}

// MarshalDERCallDateTime encodes a typed standalone CallDateTime using DER.
func MarshalDERCallDateTime(value *BERValue[CallDateTime]) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: required CallDateTime is nil", ber.ErrInvalidValue)
	}
	v := &struct{ Value CallDateTime }{Value: value.Value}
	_ = v
	var children []byte
	if len((v.Value).String()) < 14 || len((v.Value).String()) > 24 {
		if constraintErr := checkEncodedLength(nil, s581f3f_22, "37.4", "CallDateTime", "SIZE (14..24)", len((v.Value).String())); constraintErr != nil {
			return nil, constraintErr
		}
	}
	{
		if timeErr := checkEncodedEditionTime(v.Value, s581f3f_22, "CallDateTime"); timeErr != nil {
			return nil, timeErr
		}
		canonicalTimeSize, timeSizeErr := (v.Value).Canonical()
		if timeSizeErr != nil {
			return nil, timeSizeErr
		}
		if len((canonicalTimeSize).String()) < 14 || len((canonicalTimeSize).String()) > 24 {
			if constraintErr := checkEncodedLength(nil, s581f3f_22, "37.4", "CallDateTime", "SIZE (14..24)", len((canonicalTimeSize).String())); constraintErr != nil {
				return nil, constraintErr
			}
		}
	}
	enc_value, encodeErr_enc_value := encodeEditionGeneralizedTimeDER(v.Value, s581f3f_22, "CallDateTime")
	if encodeErr_enc_value != nil {
		if _, timeViolation := encodeErr_enc_value.(*ber.ValidationError); timeViolation {
			return nil, encodeErr_enc_value
		}

		return nil, fmt.Errorf("%s: %w", "encoding CallDateTime", qualifyBERError(encodeErr_enc_value, "", "encoding", true))
	}
	children = append(children, enc_value...)
	return children, nil
}

// UnmarshalBERCallDateTime decodes one complete typed standalone CallDateTime from BER/DER.
func UnmarshalBERCallDateTime(data []byte, opts ...ber.DecodeOption) (returnValue *BERValue[CallDateTime], returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERCallDateTime(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_22, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	v := &struct{ Value CallDateTime }{}
	decode := func() error {
		content := data
		offset := 0
		ber.MarkPreflightTarget(opts, "CallDateTime", content[offset:])
		val_value, n, err := decodeEditionGeneralizedTime(content[offset:], s581f3f_22, "CallDateTime", opts...)
		if err != nil {
			if _, timeViolation := err.(*ber.ValidationError); timeViolation {
				return err
			}

			return fmt.Errorf("%s: %w", "decoding CallDateTime", qualifyBERError(err, "", "decoding", false))
		}
		v.Value = val_value
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len((v.Value).String()) < 14 || len((v.Value).String()) > 24 {
			if constraintErr := checkDecodedLength(opts, s581f3f_22, "37.4", "CallDateTime", "SIZE (14..24)", len((v.Value).String())); constraintErr != nil {
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
	decoded := &BERValue[CallDateTime]{Value: v.Value}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERCallDateTime); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes AuthenticationSet to BER format.
func (v *AuthenticationSet) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: AuthenticationSet receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*AuthenticationSet).MarshalBER, (*AuthenticationSet).marshalBER, 3)

}
func (v *AuthenticationSet) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := checkEncodedLength(opts, s581f3f_23, "37.4", "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_rand, encodeErr_enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	if encodeErr_enc_rand != nil {
		return nil, qualifyBERError(encodeErr_enc_rand, "rand", "encoding", false)
	}
	children = append(children, enc_rand...)
	if len(v.Sres) < 4 || len(v.Sres) > 4 {
		if constraintErr := checkEncodedLength(opts, s581f3f_23, "37.4", "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sres, encodeErr_enc_sres := ber.EncodeOctetString([]byte(v.Sres))
	if encodeErr_enc_sres != nil {
		return nil, qualifyBERError(encodeErr_enc_sres, "sres", "encoding", false)
	}
	children = append(children, enc_sres...)
	if len(v.Kc) < 8 || len(v.Kc) > 8 {
		if constraintErr := checkEncodedLength(opts, s581f3f_23, "37.4", "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(v.Kc))
	if encodeErr_enc_kc != nil {
		return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", false)
	}
	children = append(children, enc_kc...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *AuthenticationSet) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes AuthenticationSet to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *AuthenticationSet) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AuthenticationSet receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := checkEncodedLength(nil, s581f3f_23, "37.4", "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_rand, encodeErr_enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	if encodeErr_enc_rand != nil {
		return nil, qualifyBERError(encodeErr_enc_rand, "rand", "encoding", true)
	}
	children = append(children, enc_rand...)
	if len(v.Sres) < 4 || len(v.Sres) > 4 {
		if constraintErr := checkEncodedLength(nil, s581f3f_23, "37.4", "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_sres, encodeErr_enc_sres := ber.EncodeOctetString([]byte(v.Sres))
	if encodeErr_enc_sres != nil {
		return nil, qualifyBERError(encodeErr_enc_sres, "sres", "encoding", true)
	}
	children = append(children, enc_sres...)
	if len(v.Kc) < 8 || len(v.Kc) > 8 {
		if constraintErr := checkEncodedLength(nil, s581f3f_23, "37.4", "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(v.Kc))
	if encodeErr_enc_kc != nil {
		return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", true)
	}
	children = append(children, enc_kc...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AuthenticationSet as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *AuthenticationSet) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes AuthenticationSet from BER/DER format.
func (destination *AuthenticationSet) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: AuthenticationSet destination is nil", ber.ErrInvalidValue)
	}
	v := new(AuthenticationSet)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe AuthenticationSet
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_23, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = AuthenticationSet{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*AuthenticationSet).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding AuthenticationSet SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticationSet", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode rand
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field rand", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "rand", content[offset:])
		val_rand, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "rand", "decoding", false)
		}
		v.Rand = Rand(val_rand)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Rand) < 16 || len(v.Rand) > 16 {
			if constraintErr := checkDecodedLength(opts, s581f3f_23, "37.4", "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode sres
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field sres", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "sres", content[offset:])
		val_sres, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "sres", "decoding", false)
		}
		v.Sres = Sres(val_sres)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Sres) < 4 || len(v.Sres) > 4 {
			if constraintErr := checkDecodedLength(opts, s581f3f_23, "37.4", "sres", "SIZE (4)", len(v.Sres)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode kc
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field kc", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "kc", content[offset:])
		val_kc, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "kc", "decoding", false)
		}
		v.Kc = Kc(val_kc)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Kc) < 8 || len(v.Kc) > 8 {
			if constraintErr := checkDecodedLength(opts, s581f3f_23, "37.4", "kc", "SIZE (8)", len(v.Kc)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AuthenticationSet", Cause: ber.ErrUnexpectedElement}
	}
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
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s581f3f_24, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "imsi", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMRPDAChoiceLMsId:
		if v.LMsId == nil {
			return nil, fmt.Errorf("%w: choice SMRPDA: lMsId is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.LMsId))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "lMsId", "encoding", false)
		}
		if len(*v.LMsId) < 4 || len(*v.LMsId) > 4 {
			if constraintErr := checkEncodedLength(opts, s581f3f_24, "37.4", "lMsId", "SIZE (4)", len(*v.LMsId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "lMsId", "encoding", false)
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
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, s581f3f_24, "37.4", "roamingNumber", "SIZE (1..10)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, s581f3f_24, "37.4", "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "roamingNumber", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SMRPDAChoiceServiceCentreAddress:
		if v.ServiceCentreAddress == nil {
			return nil, fmt.Errorf("%w: choice SMRPDA: serviceCentreAddress is nil", ber.ErrInvalidValue)
		}
		enc_3, encodeErr_enc_3 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddress))
		if encodeErr_enc_3 != nil {
			return nil, qualifyBERError(encodeErr_enc_3, "serviceCentreAddress", "encoding", false)
		}
		if len(*v.ServiceCentreAddress) < 1 || len(*v.ServiceCentreAddress) > 20 {
			if constraintErr := checkEncodedLength(opts, s581f3f_24, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(*v.ServiceCentreAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "serviceCentreAddress", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
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
		case SMRPDAChoiceLMsId:
			return nil, qualifyBERError(err, "lMsId", "encoding", true)
		case SMRPDAChoiceRoamingNumber:
			return nil, qualifyBERError(err, "roamingNumber", "encoding", true)
		case SMRPDAChoiceServiceCentreAddress:
			return nil, qualifyBERError(err, "serviceCentreAddress", "encoding", true)
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_24, opts)
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
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, s581f3f_24, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SMRPDAChoiceLMsId
		ber.MarkPreflightTarget(opts, "lMsId", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "lMsId", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "lMsId", "decoding", false)
		}
		tmp := LMsId(decVal)
		v.LMsId = &tmp
		if len(*v.LMsId) < 4 || len(*v.LMsId) > 4 {
			if constraintErr := checkDecodedLength(opts, s581f3f_24, "37.4", "lMsId", "SIZE (4)", len(*v.LMsId)); constraintErr != nil {
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
		tmp := IsdnAddressString(decVal)
		v.RoamingNumber = &tmp
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, s581f3f_24, "37.4", "roamingNumber", "SIZE (1..10)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, s581f3f_24, "37.4", "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPDAChoiceServiceCentreAddress
		ber.MarkPreflightTarget(opts, "serviceCentreAddress", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "serviceCentreAddress", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "serviceCentreAddress", "decoding", false)
		}
		tmp := AddressString(decVal)
		v.ServiceCentreAddress = &tmp
		if len(*v.ServiceCentreAddress) < 1 || len(*v.ServiceCentreAddress) > 20 {
			if constraintErr := checkDecodedLength(opts, s581f3f_24, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(*v.ServiceCentreAddress)); constraintErr != nil {
				return constraintErr
			}
		}
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
	case SMRPOAChoiceMsIsdn:
		if v.MsIsdn == nil {
			return nil, fmt.Errorf("%w: choice SMRPOA: msIsdn is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.MsIsdn))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "msIsdn", "encoding", false)
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkEncodedLength(opts, s581f3f_25, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkEncodedLength(opts, s581f3f_25, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "msIsdn", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SMRPOAChoiceServiceCentreAddress:
		if v.ServiceCentreAddress == nil {
			return nil, fmt.Errorf("%w: choice SMRPOA: serviceCentreAddress is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.ServiceCentreAddress))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "serviceCentreAddress", "encoding", false)
		}
		if len(*v.ServiceCentreAddress) < 1 || len(*v.ServiceCentreAddress) > 20 {
			if constraintErr := checkEncodedLength(opts, s581f3f_25, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(*v.ServiceCentreAddress)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "serviceCentreAddress", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
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
		case SMRPOAChoiceMsIsdn:
			return nil, qualifyBERError(err, "msIsdn", "encoding", true)
		case SMRPOAChoiceServiceCentreAddress:
			return nil, qualifyBERError(err, "serviceCentreAddress", "encoding", true)
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
	opts = ber.TrackGSM0902Phase1Form(opts)
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
	opts = ber.LocateDecodedElement(data, s581f3f_25, opts)
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

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
		v.Choice = SMRPOAChoiceMsIsdn
		ber.MarkPreflightTarget(opts, "msIsdn", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "msIsdn", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msIsdn", "decoding", false)
		}
		tmp := IsdnAddressString(decVal)
		v.MsIsdn = &tmp
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkDecodedLength(opts, s581f3f_25, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkDecodedLength(opts, s581f3f_25, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SMRPOAChoiceServiceCentreAddress
		ber.MarkPreflightTarget(opts, "serviceCentreAddress", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "serviceCentreAddress", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "serviceCentreAddress", "decoding", false)
		}
		tmp := AddressString(decVal)
		v.ServiceCentreAddress = &tmp
		if len(*v.ServiceCentreAddress) < 1 || len(*v.ServiceCentreAddress) > 20 {
			if constraintErr := checkDecodedLength(opts, s581f3f_25, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(*v.ServiceCentreAddress)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for SMRPOA CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBERRequestParameters encodes a RequestParameters list to BER.
func MarshalBERRequestParameters(collection *RequestParameters, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERRequestParameters, marshalBERRequestParameters, 3, UnmarshalBERRequestParameters)

}
func marshalBERRequestParameters(collection *RequestParameters, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 2 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERRequestParameters", "37.4", "RequestParameters", "SIZE (1..2)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if int64(elem) != 0 && int64(elem) != 1 && int64(elem) != 2 && int64(elem) != 3 && int64(elem) != 4 {
			if constraintErr := checkEncodedValue(opts, "MAP-DataTypes.marshalBERRequestParameters", "15", fmt.Sprintf("element[%d]", elemIndex), "ENUMERATED {0, 1, 2, 3, 4}", fmt.Sprint(int64(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ber.EncodeEnumerated(int64(elem))...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}

func appendBERLinearRequestParameters(encoder *ber.LinearEncoder, collection *RequestParameters, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERRequestParameters(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERRequestParameters encodes a RequestParameters list to DER.
func MarshalDERRequestParameters(collection *RequestParameters) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 2 {
		if constraintErr := checkEncodedCollectionLength(nil, s581f3f_26, "37.4", "RequestParameters", "SIZE (1..2)", len(list)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	var children []byte
	for elemIndex, elem := range list {
		_ = elemIndex
		if int64(elem) != 0 && int64(elem) != 1 && int64(elem) != 2 && int64(elem) != 3 && int64(elem) != 4 {
			if constraintErr := checkEncodedValue(nil, s581f3f_26, "15", fmt.Sprintf("element[%d]", elemIndex), "ENUMERATED {0, 1, 2, 3, 4}", fmt.Sprint(int64(elem))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		children = append(children, ber.EncodeEnumerated(int64(elem))...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RequestParameters as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearRequestParameters(encoder *ber.LinearEncoder, collection *RequestParameters) ([]byte, error) {
	encoded, err := MarshalDERRequestParameters(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERRequestParameters decodes a RequestParameters list from BER.
func UnmarshalBERRequestParameters(data []byte, opts ...ber.DecodeOption) (returnValue *RequestParameters, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERRequestParameters(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_26, opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding RequestParameters", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "RequestParameters", Cause: ber.ErrExtraData}
	}
	var result []RequestParameter
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		val, n, intErr := ber.DecodeEnumerated(elementData, opts...)
		if intErr != nil {
			return nil, qualifyBERError(intErr, fmt.Sprintf("element[%d]",
				elementIndex),

				"decoding", false)
		}
		if val != 0 && val != 1 && val != 2 && val != 3 && val != 4 {
			if constraintErr := checkDecodedValue(opts, s581f3f_26, "15", fmt.Sprintf("element[%d]", len(result)), "ENUMERATED {0, 1, 2, 3, 4}", fmt.Sprint(val)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		result = append(result, RequestParameter(val))
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return nil, fmt.Errorf("invalid BER content window")
		}

		offset += n
	}
	if len(result) < 1 || len(result) > 2 {
		if constraintErr := checkDecodedCollectionLength(opts, s581f3f_26, "37.4", "RequestParameters", "SIZE (1..2)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &RequestParameters{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERRequestParameters); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes SentParameter to BER format.
func (v *SentParameter) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SentParameter receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SentParameter).MarshalBER, (*SentParameter).marshalBER, 3)

}
func (v *SentParameter) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SentParameter) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SentParameterChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, s581f3f_27, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "imsi", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SentParameterChoiceAuthenticationSet:
		if v.AuthenticationSet == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: authenticationSet is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.AuthenticationSet.MarshalBER(ber.ChildEncodeOptions(opts, "authenticationSet")...)
		if err != nil {
			return nil, qualifyBERError(err, "authenticationSet", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "authenticationSet", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case SentParameterChoiceSusbcriberData:
		if v.SusbcriberData == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: susbcriberData is nil", ber.ErrInvalidValue)
		}
		enc_2, err := v.SusbcriberData.MarshalBER(ber.ChildEncodeOptions(opts, "susbcriberData")...)
		if err != nil {
			return nil, qualifyBERError(err, "susbcriberData", "encoding", false)
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "susbcriberData", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case SentParameterChoiceCugInformation:
		if v.CugInformation == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: cug-information is nil", ber.ErrInvalidValue)
		}
		enc_3, err := v.CugInformation.MarshalBER(ber.ChildEncodeOptions(opts, "cug-information")...)
		if err != nil {
			return nil, qualifyBERError(err, "cug-information", "encoding", false)
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "cug-information", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	case SentParameterChoiceKi:
		if v.Ki == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: ki is nil", ber.ErrInvalidValue)
		}
		enc_4, encodeErr_enc_4 := ber.EncodeOctetString([]byte(*v.Ki))
		if encodeErr_enc_4 != nil {
			return nil, qualifyBERError(encodeErr_enc_4, "ki", "encoding", false)
		}
		if len(*v.Ki) < 16 || len(*v.Ki) > 16 {
			if constraintErr := checkEncodedLength(opts, s581f3f_27, "37.4", "ki", "SIZE (16)", len(*v.Ki)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_4, tagErr_enc_4 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_4)
		if tagErr_enc_4 != nil {
			return nil, qualifyBERError(tagErr_enc_4, "ki", "encoding", false)
		}
		enc_4 = retagged_enc_4
		return enc_4, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SentParameter", v.Choice)
	}
}

// MarshalDER encodes SentParameter to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SentParameter) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SentParameter receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SentParameterChoiceAuthenticationSet:
		if v.AuthenticationSet == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: authenticationSet is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.AuthenticationSet.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "authenticationSet", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "authenticationSet", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "authenticationSet", "encoding", true)
		}
		return enc_der_1, nil
	case SentParameterChoiceSusbcriberData:
		if v.SusbcriberData == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: susbcriberData is nil", ber.ErrInvalidValue)
		}
		enc_der_2, err := v.SusbcriberData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "susbcriberData", "encoding", true)
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "susbcriberData", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "susbcriberData", "encoding", true)
		}
		return enc_der_2, nil
	case SentParameterChoiceCugInformation:
		if v.CugInformation == nil {
			return nil, fmt.Errorf("%w: choice SentParameter: cug-information is nil", ber.ErrInvalidValue)
		}
		enc_der_3, err := v.CugInformation.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cug-information", "encoding", true)
		}
		retagged_enc_der_3, tagErr_enc_der_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_der_3)
		if tagErr_enc_der_3 != nil {
			return nil, qualifyBERError(tagErr_enc_der_3, "cug-information", "encoding", true)
		}
		enc_der_3 = retagged_enc_der_3
		if derErr := ber.ValidateDEREncodedElement(enc_der_3); derErr != nil {
			return nil, qualifyBERError(derErr, "cug-information", "encoding", true)
		}
		return enc_der_3, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SentParameterChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case SentParameterChoiceAuthenticationSet:
			return nil, qualifyBERError(err, "authenticationSet", "encoding", true)
		case SentParameterChoiceSusbcriberData:
			return nil, qualifyBERError(err, "susbcriberData", "encoding", true)
		case SentParameterChoiceCugInformation:
			return nil, qualifyBERError(err, "cug-information", "encoding", true)
		case SentParameterChoiceKi:
			return nil, qualifyBERError(err, "ki", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SentParameter as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SentParameter) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SentParameter from BER/DER format.
func (destination *SentParameter) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SentParameter destination is nil", ber.ErrInvalidValue)
	}
	v := new(SentParameter)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SentParameter).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SentParameter
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_27, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SentParameter{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SentParameter CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SentParameter: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SentParameter CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SentParameter", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SentParameter.authenticationSet", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SentParameter.susbcriberData", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SentParameter.cug-information", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SentParameterChoiceImsi
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
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, s581f3f_27, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = SentParameterChoiceAuthenticationSet
		ber.MarkPreflightTarget(opts, "authenticationSet", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "authenticationSet", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec AuthenticationSet
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "authenticationSet")...); unmErr != nil {
			return qualifyBERError(unmErr, "authenticationSet", "decoding", false)
		}
		v.AuthenticationSet = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = SentParameterChoiceSusbcriberData
		ber.MarkPreflightTarget(opts, "susbcriberData", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "susbcriberData", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec SubscriberData
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "susbcriberData")...); unmErr != nil {
			return qualifyBERError(unmErr, "susbcriberData", "decoding", false)
		}
		v.SusbcriberData = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = SentParameterChoiceCugInformation
		ber.MarkPreflightTarget(opts, "cug-information", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "cug-information", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec CUGInformation
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "cug-information")...); unmErr != nil {
			return qualifyBERError(unmErr, "cug-information", "decoding", false)
		}
		v.CugInformation = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
		v.Choice = SentParameterChoiceKi
		ber.MarkPreflightTarget(opts, "ki", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "ki", "decoding", false)
		}
		_ = rawVal
		decVal, octetErr := ber.DecodeImplicitOctetStringValue(peekTag.Constructed, rawVal, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "ki", "decoding", false)
		}
		tmp := Ki(decVal)
		v.Ki = &tmp
		if len(*v.Ki) < 16 || len(*v.Ki) > 16 {
			if constraintErr := checkDecodedLength(opts, s581f3f_27, "37.4", "ki", "SIZE (16)", len(*v.Ki)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for SentParameter CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBERSentParameters encodes a SentParameters list to BER.
func MarshalBERSentParameters(collection *SentParameters, opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(collection, collection.berReplayNode_, opts, MarshalBERSentParameters, marshalBERSentParameters, 3, UnmarshalBERSentParameters)

}
func marshalBERSentParameters(collection *SentParameters, opts ...ber.EncodeOption) ([]byte, error) {
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := checkEncodedCollectionLength(opts, "MAP-DataTypes.marshalBERSentParameters", "37.4", "SentParameters", "SIZE (1..10)", len(list)); constraintErr != nil {
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

func appendBERLinearSentParameters(encoder *ber.LinearEncoder, collection *SentParameters, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := MarshalBERSentParameters(collection, opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDERSentParameters encodes a SentParameters list to DER.
func MarshalDERSentParameters(collection *SentParameters) ([]byte, error) {
	if collection == nil {
		return nil, fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue)
	}
	list := collection.Values
	if len(list) < 1 || len(list) > 10 {
		if constraintErr := checkEncodedCollectionLength(nil, "MAP-DataTypes.SentParameters", "37.4", "SentParameters", "SIZE (1..10)", len(list)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding SentParameters as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func appendDERLinearSentParameters(encoder *ber.LinearEncoder, collection *SentParameters) ([]byte, error) {
	encoded, err := MarshalDERSentParameters(collection)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBERSentParameters decodes a SentParameters list from BER.
func UnmarshalBERSentParameters(data []byte, opts ...ber.DecodeOption) (returnValue *SentParameters, returnErr error) {
	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return nil, ownErr
	}
	data = ownedData
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return nil, ber.DiagnosePreflight(prepareErr, data, opts, "element", func(probeOpts []ber.DecodeOption) error {
			_, probeErr := UnmarshalBERSentParameters(data, probeOpts...)
			return probeErr
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-DataTypes.SentParameters", opts)
	defer func() {
		returnErr = ber.LocateDecodeError(returnErr, opts)
		if returnErr != nil {
			returnValue = nil
		}
	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", "decoding SentParameters", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return nil, &ber.DecodeError{Offset: total, TypeName: "SentParameters", Cause: ber.ErrExtraData}
	}
	var result []SentParameter
	offset := 0
	for offset < len(content) {
		elementIndex := len(result)
		_ = elementIndex
		elementData := content[offset:]
		ber.MarkPreflightElement(opts, elementIndex, elementData)
		var elem SentParameter
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
		if constraintErr := checkDecodedCollectionLength(opts, "MAP-DataTypes.SentParameters", "37.4", "SentParameters", "SIZE (1..10)", len(result)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	decoded := &SentParameters{Values: result}
	if replayErr := completeValueBER(data,
		opts, decoded, &decoded.berReplayNode_, MarshalBERSentParameters); replayErr != nil {
		return nil, replayErr
	}

	return decoded, nil
}

// MarshalBER encodes CUGInformationComponent1 to BER format.
func (v *CUGInformationComponent1) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CUGInformationComponent1 receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CUGInformationComponent1).MarshalBER, (*CUGInformationComponent1).marshalBER, 3)

}
func (v *CUGInformationComponent1) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *CUGInformationComponent1) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CUGInformationComponent1ChoiceCugFeature:
		if v.CugFeature == nil {
			return nil, fmt.Errorf("%w: choice CUGInformationComponent1: cug-Feature is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.CugFeature.MarshalBER(ber.ChildEncodeOptions(opts, "cug-Feature")...)
		if err != nil {
			return nil, qualifyBERError(err, "cug-Feature", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "cug-Feature", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case CUGInformationComponent1ChoiceCugFeatureList:
		enc_1, err := MarshalBERCUGFeatureList(v.CugFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "cug-FeatureList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "cug-FeatureList", "encoding", false)
		}
		if len((v.CugFeatureList).Values) < 1 || len((v.CugFeatureList).Values) > 10 {
			if constraintErr := checkEncodedLength(opts, s581f3f_28, "37.4", "cug-FeatureList", "SIZE (1..10)", len((v.CugFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "cug-FeatureList", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CUGInformationComponent1", v.Choice)
	}
}

// MarshalDER encodes CUGInformationComponent1 to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CUGInformationComponent1) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CUGInformationComponent1 receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case CUGInformationComponent1ChoiceCugFeature:
		if v.CugFeature == nil {
			return nil, fmt.Errorf("%w: choice CUGInformationComponent1: cug-Feature is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.CugFeature.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "cug-Feature", "encoding", true)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "cug-Feature", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "cug-Feature", "encoding", true)
		}
		return enc_der_0, nil
	case CUGInformationComponent1ChoiceCugFeatureList:
		enc_der_1, err := MarshalDERCUGFeatureList(v.CugFeatureList)
		if err != nil {
			return nil, qualifyBERError(err, "cug-FeatureList", "encoding", true)
		}
		if len((v.CugFeatureList).Values) < 1 || len((v.CugFeatureList).Values) > 10 {
			if constraintErr := checkEncodedLength(nil, s581f3f_28, "37.4", "cug-FeatureList", "SIZE (1..10)", len((v.CugFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "cug-FeatureList", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "cug-FeatureList", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case CUGInformationComponent1ChoiceCugFeature:
			return nil, qualifyBERError(err, "cug-Feature", "encoding", true)
		case CUGInformationComponent1ChoiceCugFeatureList:
			return nil, qualifyBERError(err, "cug-FeatureList", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding CUGInformationComponent1 as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *CUGInformationComponent1) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CUGInformationComponent1 from BER/DER format.
func (destination *CUGInformationComponent1) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CUGInformationComponent1 destination is nil", ber.ErrInvalidValue)
	}
	v := new(CUGInformationComponent1)

	defer publishDecodedValue(destination, v, &returnErr)

	opts, commitReports := ber.StageDecodeReports(opts)
	defer func() { commitReports(returnErr == nil) }()
	opts = ber.TrackGSM0902Phase1Form(opts)
	ownedData, ownErr := ber.OwnGeneratedBERInput(data, opts)
	if ownErr != nil {
		return ownErr
	}
	data = ownedData
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CUGInformationComponent1).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CUGInformationComponent1
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, s581f3f_28, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CUGInformationComponent1{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CUGInformationComponent1 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CUGInformationComponent1: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding CUGInformationComponent1 CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CUGInformationComponent1", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "CUGInformationComponent1.cug-Feature", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "CUGInformationComponent1.cug-FeatureList", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = CUGInformationComponent1ChoiceCugFeature
		ber.MarkPreflightTarget(opts, "cug-Feature", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "cug-Feature", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec CUGFeature
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "cug-Feature")...); unmErr != nil {
			return qualifyBERError(unmErr, "cug-Feature", "decoding", false)
		}
		v.CugFeature = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = CUGInformationComponent1ChoiceCugFeatureList
		ber.MarkPreflightTarget(opts, "cug-FeatureList", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "cug-FeatureList", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERCUGFeatureList(reconstructed, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "cug-FeatureList"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "cug-FeatureList", "decoding", false)
		}
		v.CugFeatureList = dec
		if len((v.CugFeatureList).Values) < 1 || len((v.CugFeatureList).Values) > 10 {
			if constraintErr := checkDecodedLength(opts, s581f3f_28, "37.4", "cug-FeatureList", "SIZE (1..10)", len((v.CugFeatureList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for CUGInformationComponent1 CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

const (
	s581f3f_0  = "MAP-DataTypes.IsdnAddressString"
	s581f3f_1  = "MAP-DataTypes.ExternalSignalInfo"
	s581f3f_2  = "MAP-DataTypes.SubscriberId"
	s581f3f_3  = "MAP-DataTypes.LocationInfo"
	s581f3f_4  = "MAP-DataTypes.HlrList"
	s581f3f_5  = "MAP-DataTypes.BearerServiceList"
	s581f3f_6  = "MAP-DataTypes.TeleserviceList"
	s581f3f_7  = "MAP-DataTypes.BasicServiceCode"
	s581f3f_8  = "MAP-DataTypes.SS-CodeList"
	s581f3f_9  = "MAP-DataTypes.SS-Data"
	s581f3f_10 = "MAP-DataTypes.SS-SubscriptionOption"
	s581f3f_11 = "MAP-DataTypes.CUG-Feature"
	s581f3f_12 = "MAP-DataTypes.CUG-Information"
	s581f3f_13 = "MAP-DataTypes.ForwardingInfo"
	s581f3f_14 = "MAP-DataTypes.ForwardingData"
	s581f3f_15 = "MAP-DataTypes.ForwardingFeature"
	s581f3f_16 = "MAP-DataTypes.CallBarringInfo"
	s581f3f_17 = "MAP-DataTypes.CallBarringFeature"
	s581f3f_18 = "MAP-DataTypes.SubscriberData"
	s581f3f_19 = "MAP-DataTypes.Password"
	s581f3f_20 = "MAP-DataTypes.SS-UserData"
	s581f3f_21 = "MAP-DataTypes.SS-ChargingData"
	s581f3f_22 = "MAP-DataTypes.CallDateTime"
	s581f3f_23 = "MAP-DataTypes.AuthenticationSet"
	s581f3f_24 = "MAP-DataTypes.SM-RP-DA"
	s581f3f_25 = "MAP-DataTypes.SM-RP-OA"
	s581f3f_26 = "MAP-DataTypes.RequestParameters"
	s581f3f_27 = "MAP-DataTypes.SentParameter"
	s581f3f_28 = "MAP-DataTypes.CUG-Information-component1"
)
