// Code generated from ASN.1 module "MAP-Operations". DO NOT EDIT.

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

// ActivateSSArgument represents the ASN.1 type ActivateSS-argument (SEQUENCE).
type ActivateSSArgument struct {
	SsCode         SSCode            `asn1:""`
	BasicService   *BasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// ActivateTraceModeArgument represents the ASN.1 type ActivateTraceMode-argument (SEQUENCE).
type ActivateTraceModeArgument struct {
	Imsi           *IMSI           `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference TraceReference  `asn1:"tag:1,context,implicit"`
	TraceType      TraceType       `asn1:"tag:2,context,implicit"`
	OmcId          *AddressString  `asn1:"tag:3,context,implicit,optional" json:"OmcId,omitempty"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// AlertServiceCentreArgument represents the ASN.1 type AlertServiceCentre-argument (SEQUENCE).
type AlertServiceCentreArgument struct {
	MsIsdn               IsdnAddressString `asn1:""`
	ServiceCentreAddress AddressString     `asn1:""`
	berReplayNode_       *ber.ReplayNode   `asn1:"-" json:"-"`
}

// AuthenticateArgument represents the ASN.1 type Authenticate-argument (SEQUENCE).
type AuthenticateArgument struct {
	Rand           Rand            `asn1:""`
	Cksn           CKSN            `asn1:""`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// BeginSubscriberActivityArgument represents the ASN.1 type BeginSubscriberActivity-argument (SEQUENCE).
type BeginSubscriberActivityArgument struct {
	Imsi                    IMSI              `asn1:""`
	OriginatingEntityNumber IsdnAddressString `asn1:""`
	berReplayNode_          *ber.ReplayNode   `asn1:"-" json:"-"`
}

// CancelLocationArgument choice constants.
const (
	CancelLocationArgumentChoiceImsi = 1
	// CancelLocationArgumentChoiceAlternative1 selects the anonymous alternative at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 24.1.
	CancelLocationArgumentChoiceAlternative1 = 2
)

// CancelLocationArgument represents the ASN.1 CHOICE type CancelLocation-argument.
type CancelLocationArgument struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	Imsi           *IMSI           `json:"Imsi,omitempty"`
	// Alternative1 is the anonymous alternative at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 24.1.
	Alternative1 *CancelLocationArgumentAlternative1 `json:"Alternative1,omitempty"`
}

// NewCancelLocationArgumentImsi creates a CancelLocationArgument with the imsi alternative.
func NewCancelLocationArgumentImsi(v IMSI) CancelLocationArgument {
	return CancelLocationArgument{
		Choice: CancelLocationArgumentChoiceImsi,
		Imsi:   &v,
	}
}

// NewCancelLocationArgumentAlternative1 creates a CancelLocationArgument with the alternative1 alternative.
func NewCancelLocationArgumentAlternative1(v CancelLocationArgumentAlternative1) CancelLocationArgument {
	return CancelLocationArgument{
		Choice:       CancelLocationArgumentChoiceAlternative1,
		Alternative1: &v,
	}
}

// CompleteCallArgument represents the ASN.1 type CompleteCall-argument (SEQUENCE).
type CompleteCallArgument struct {
	MsIsdn               IsdnAddressString     `asn1:"tag:0,context,implicit"`
	Category             *Category             `asn1:"tag:1,context,implicit,optional" json:"Category,omitempty"`
	CugIndex             *CUGIndex             `asn1:"tag:2,context,implicit,optional" json:"CugIndex,omitempty"`
	GSMBearerCapability  *ExternalSignalInfo   `asn1:"tag:3,context,implicit,optional" json:"GSMBearerCapability,omitempty"`
	NoReplyConditionTime *NoReplyConditionTime `asn1:"tag:4,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	SsDataList           *SSDataList           `asn1:"tag:5,context,implicit,optional" json:"SsDataList,omitempty"`
	berSsDataListIndef_  bool                  `asn1:"-" json:"-"`
	berReplayNode_       *ber.ReplayNode       `asn1:"-" json:"-"`
}

// ConnectToFollowingAddressArgument represents the ASN.1 type ConnectToFollowingAddress-argument (SEQUENCE).
type ConnectToFollowingAddressArgument struct {
	ForwardingData ForwardingData     `asn1:""`
	MsIsdn         *IsdnAddressString `asn1:",optional" json:"MsIsdn,omitempty"`
	berReplayNode_ *ber.ReplayNode    `asn1:"-" json:"-"`
}

// DeactivateSSArgument represents the ASN.1 type DeactivateSS-argument (SEQUENCE).
type DeactivateSSArgument struct {
	SsCode         SSCode            `asn1:""`
	BasicService   *BasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// DeactivateTraceModeArgument represents the ASN.1 type DeactivateTraceMode-argument (SEQUENCE).
type DeactivateTraceModeArgument struct {
	Imsi           *IMSI           `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference TraceReference  `asn1:"tag:1,context,implicit"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// DeleteSubscriberDataArgument represents the ASN.1 type DeleteSubscriberData-argument (SEQUENCE).
type DeleteSubscriberDataArgument struct {
	Imsi                  IMSI              `asn1:"tag:0,context,implicit"`
	BasicService          *BasicServiceList `asn1:"tag:1,context,implicit,optional" json:"BasicService,omitempty"`
	berBasicServiceIndef_ bool              `asn1:"-" json:"-"`
	SsCode                *SSCodeList       `asn1:"tag:2,context,implicit,optional" json:"SsCode,omitempty"`
	berSsCodeIndef_       bool              `asn1:"-" json:"-"`
	berReplayNode_        *ber.ReplayNode   `asn1:"-" json:"-"`
}

// EraseSSArgument represents the ASN.1 type EraseSS-argument (SEQUENCE).
type EraseSSArgument struct {
	SsCode         SSCode            `asn1:""`
	BasicService   *BasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// ForwardShortMessageArgument represents the ASN.1 type ForwardShortMessage-argument (SEQUENCE).
type ForwardShortMessageArgument struct {
	SmRPDA         SMRPDA          `asn1:""`
	SmRPOA         SMRPOA          `asn1:""`
	SmRPUI         SMRPUI          `asn1:""`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// ForwardSsNotificationArgument represents the ASN.1 type ForwardSsNotification-argument (SEQUENCE).
type ForwardSsNotificationArgument struct {
	Imsi           *IMSI              `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	SsCode         *SSCode            `asn1:"tag:1,context,implicit,optional" json:"SsCode,omitempty"`
	Teleservice    *TeleserviceCode   `asn1:"tag:2,context,implicit,optional" json:"Teleservice,omitempty"`
	BearerService  *BearerServiceCode `asn1:"tag:3,context,implicit,optional" json:"BearerService,omitempty"`
	SsStatus       *SSStatus          `asn1:"tag:4,context,implicit,optional" json:"SsStatus,omitempty"`
	SsNotification *SSNotification    `asn1:"tag:5,context,implicit,optional" json:"SsNotification,omitempty"`
	berReplayNode_ *ber.ReplayNode    `asn1:"-" json:"-"`
}

// InsertSubscriberDataArgument represents the ASN.1 type InsertSubscriberData-argument (SEQUENCE).
type InsertSubscriberDataArgument struct {
	Imsi                             *IMSI              `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
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

// InterrogateSSArgument represents the ASN.1 type InterrogateSS-argument (SEQUENCE).
type InterrogateSSArgument struct {
	SsCode         SSCode            `asn1:""`
	BasicService   *BasicServiceCode `asn1:",optional" json:"BasicService,omitempty"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// InterrogateSSResult choice constants.
const (
	InterrogateSSResultChoiceSsStatus              = 1
	InterrogateSSResultChoiceForwardedToNumber     = 2
	InterrogateSSResultChoiceActivesBasicServices  = 3
	InterrogateSSResultChoiceForwardingFeatureList = 4
)

// InterrogateSSResult represents the ASN.1 CHOICE type InterrogateSS-result.
type InterrogateSSResult struct {
	Choice                int
	berReplayNode_        *ber.ReplayNode        `json:"-"`
	SsStatus              *SSStatus              `json:"SsStatus,omitempty"`
	ForwardedToNumber     *IsdnAddressString     `json:"ForwardedToNumber,omitempty"`
	ActivesBasicServices  *BasicServiceList      `json:"ActivesBasicServices,omitempty"`
	ForwardingFeatureList *ForwardingFeatureList `json:"ForwardingFeatureList,omitempty"`
}

// NewInterrogateSSResultSsStatus creates a InterrogateSSResult with the ss-Status alternative.
func NewInterrogateSSResultSsStatus(v SSStatus) InterrogateSSResult {
	return InterrogateSSResult{
		Choice:   InterrogateSSResultChoiceSsStatus,
		SsStatus: &v,
	}
}

// NewInterrogateSSResultForwardedToNumber creates a InterrogateSSResult with the forwardedToNumber alternative.
func NewInterrogateSSResultForwardedToNumber(v IsdnAddressString) InterrogateSSResult {
	return InterrogateSSResult{
		Choice:            InterrogateSSResultChoiceForwardedToNumber,
		ForwardedToNumber: &v,
	}
}

// NewInterrogateSSResultActivesBasicServices creates a InterrogateSSResult with the activesBasicServices alternative.
func NewInterrogateSSResultActivesBasicServices(v *BasicServiceList) InterrogateSSResult {
	return InterrogateSSResult{
		Choice:               InterrogateSSResultChoiceActivesBasicServices,
		ActivesBasicServices: v,
	}
}

// NewInterrogateSSResultForwardingFeatureList creates a InterrogateSSResult with the forwardingFeatureList alternative.
func NewInterrogateSSResultForwardingFeatureList(v *ForwardingFeatureList) InterrogateSSResult {
	return InterrogateSSResult{
		Choice:                InterrogateSSResultChoiceForwardingFeatureList,
		ForwardingFeatureList: v,
	}
}

// InvokeSSArgument represents the ASN.1 type InvokeSS-argument (SEQUENCE).
type InvokeSSArgument struct {
	SsCode                     SSCode                      `asn1:""`
	BasicService               *BasicServiceCode           `asn1:",optional" json:"BasicService,omitempty"`
	UserToUserServiceIndicator *UserToUserServiceIndicator `asn1:"tag:4,context,implicit,optional" json:"UserToUserServiceIndicator,omitempty"`
	CugIndex                   *CUGIndex                   `asn1:"tag:5,context,implicit,optional" json:"CugIndex,omitempty"`
	NumberOfConferees          *NumberOfConferees          `asn1:"tag:6,context,implicit,optional" json:"NumberOfConferees,omitempty"`
	berReplayNode_             *ber.ReplayNode             `asn1:"-" json:"-"`
}

// NoteInternalHandoverArgument represents the ASN.1 type NoteInternalHandover-argument (SEQUENCE).
type NoteInternalHandoverArgument struct {
	HandoverType   HandoverType        `asn1:""`
	TargetCellId   *GlobalCellId       `asn1:"tag:1,context,implicit,optional" json:"TargetCellId,omitempty"`
	ChannelId      *ExternalSignalInfo `asn1:"tag:2,context,implicit,optional" json:"ChannelId,omitempty"`
	berReplayNode_ *ber.ReplayNode     `asn1:"-" json:"-"`
}

// PageArgument represents the ASN.1 type Page-argument (SEQUENCE).
type PageArgument struct {
	Imsi           IMSI            `asn1:"tag:0,context,implicit"`
	Tmsi           *TMSI           `asn1:"tag:1,context,implicit,optional" json:"Tmsi,omitempty"`
	LocAreaId      LocAreaId       `asn1:"tag:2,context,implicit"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// PerformHandoverArgument represents the ASN.1 type PerformHandover-argument (SEQUENCE).
type PerformHandoverArgument struct {
	TargetCellId         GlobalCellId         `asn1:""`
	ServingCellId        GlobalCellId         `asn1:""`
	ChannelType          ChannelType          `asn1:""`
	ClassmarkInformation ClassmarkInformation `asn1:""`
	HandoverPriority     *HandoverPriority    `asn1:"tag:11,context,implicit,optional" json:"HandoverPriority,omitempty"`
	Kc                   *Kc                  `asn1:"tag:12,context,implicit,optional" json:"Kc,omitempty"`
	berReplayNode_       *ber.ReplayNode      `asn1:"-" json:"-"`
}

// PerformHandoverResult represents the ASN.1 type PerformHandover-result (SEQUENCE).
type PerformHandoverResult struct {
	HandoverNumber   IsdnAddressString  `asn1:""`
	AccessSignalInfo ExternalSignalInfo `asn1:""`
	berReplayNode_   *ber.ReplayNode    `asn1:"-" json:"-"`
}

// PerformSubsequentHandoverArgument represents the ASN.1 type PerformSubsequentHandover-argument (SEQUENCE).
type PerformSubsequentHandoverArgument struct {
	TargetCellId         GlobalCellId          `asn1:""`
	ServingCellId        GlobalCellId          `asn1:""`
	TargetMscNumber      IsdnAddressString     `asn1:""`
	ClassmarkInformation *ClassmarkInformation `asn1:"tag:10,context,implicit,optional" json:"ClassmarkInformation,omitempty"`
	berReplayNode_       *ber.ReplayNode       `asn1:"-" json:"-"`
}

// ProcessAccessRequestArgument represents the ASN.1 type ProcessAccessRequest-argument (SEQUENCE).
type ProcessAccessRequestArgument struct {
	SubscriberId           SubscriberId           `asn1:""`
	CmServiceType          CmServiceType          `asn1:""`
	AccessConnectionStatus AccessConnectionStatus `asn1:""`
	Cksn                   CKSN                   `asn1:""`
	berReplayNode_         *ber.ReplayNode        `asn1:"-" json:"-"`
}

// ProcessAccessRequestResult represents the ASN.1 type ProcessAccessRequest-result (SEQUENCE).
type ProcessAccessRequestResult struct {
	Imsi           IMSI               `asn1:""`
	MsIsdn         *IsdnAddressString `asn1:",optional" json:"MsIsdn,omitempty"`
	berReplayNode_ *ber.ReplayNode    `asn1:"-" json:"-"`
}

// ProvideRoamingNumberArgument represents the ASN.1 type ProvideRoamingNumber-argument (SEQUENCE).
type ProvideRoamingNumberArgument struct {
	Imsi                  IMSI                `asn1:"tag:0,context,implicit"`
	MscNumber             *IsdnAddressString  `asn1:"tag:1,context,implicit,optional" json:"MscNumber,omitempty"`
	MsIsdn                *IsdnAddressString  `asn1:"tag:2,context,implicit,optional" json:"MsIsdn,omitempty"`
	PreviousRoamingNumber *IsdnAddressString  `asn1:"tag:3,context,implicit,optional" json:"PreviousRoamingNumber,omitempty"`
	LMsId                 *LMsId              `asn1:"tag:4,context,implicit,optional" json:"LMsId,omitempty"`
	GSMBearerCapability   *ExternalSignalInfo `asn1:"tag:5,context,implicit,optional" json:"GSMBearerCapability,omitempty"`
	NetworkSignalInfo     *ExternalSignalInfo `asn1:"tag:6,context,implicit,optional" json:"NetworkSignalInfo,omitempty"`
	berReplayNode_        *ber.ReplayNode     `asn1:"-" json:"-"`
}

// RegisterChargingInformationArgument represents the ASN.1 type RegisterChargingInformation-argument (SEQUENCE).
type RegisterChargingInformationArgument struct {
	MsIsdn                  IsdnAddressString  `asn1:""`
	MscNumber               IsdnAddressString  `asn1:""`
	Imsi                    IMSI               `asn1:""`
	CallReference           CallReference      `asn1:""`
	CallType                CallType           `asn1:""`
	CallStatus              CallStatus         `asn1:""`
	CallDateTime            CallDateTime       `asn1:""`
	CallDuration            CallDuration       `asn1:""`
	BearerServiceCode       *BearerServiceCode `asn1:"tag:10,context,implicit,optional" json:"BearerServiceCode,omitempty"`
	TeleserviceCode         *TeleserviceCode   `asn1:"tag:11,context,implicit,optional" json:"TeleserviceCode,omitempty"`
	CalledNumber            *IsdnAddressString `asn1:"tag:12,context,implicit,optional" json:"CalledNumber,omitempty"`
	CallingNumber           *IsdnAddressString `asn1:"tag:13,context,implicit,optional" json:"CallingNumber,omitempty"`
	PacketDataVolume        *PacketDataVolume  `asn1:"tag:14,context,implicit,optional" json:"PacketDataVolume,omitempty"`
	ChargingUnit            *ChargingUnit      `asn1:"tag:15,context,implicit,optional" json:"ChargingUnit,omitempty"`
	Charge                  *Charge            `asn1:"tag:16,context,implicit,optional" json:"Charge,omitempty"`
	SsChargingInfo          *SSChargingInfo    `asn1:"tag:17,context,implicit,optional" json:"SsChargingInfo,omitempty"`
	berSsChargingInfoIndef_ bool               `asn1:"-" json:"-"`
	berReplayNode_          *ber.ReplayNode    `asn1:"-" json:"-"`
}

// RegisterSSArgument represents the ASN.1 type RegisterSS-argument (SEQUENCE).
type RegisterSSArgument struct {
	SsCode               SSCode                `asn1:""`
	BasicService         *BasicServiceCode     `asn1:",optional" json:"BasicService,omitempty"`
	ForwardedToNumber    *IsdnAddressString    `asn1:"tag:4,context,implicit,optional" json:"ForwardedToNumber,omitempty"`
	NoReplyConditionTime *NoReplyConditionTime `asn1:"tag:5,context,implicit,optional" json:"NoReplyConditionTime,omitempty"`
	berReplayNode_       *ber.ReplayNode       `asn1:"-" json:"-"`
}

// ResetArgument represents the ASN.1 type Reset-argument (SEQUENCE).
type ResetArgument struct {
	NetworkResource         NetworkResource   `asn1:""`
	OriginatingEntityNumber IsdnAddressString `asn1:""`
	HlrId                   *HlrList          `asn1:",optional" json:"HlrId,omitempty"`
	berHlrIdIndef_          bool              `asn1:"-" json:"-"`
	berReplayNode_          *ber.ReplayNode   `asn1:"-" json:"-"`
}

// SearchForMobileSubscriberArgument represents the ASN.1 type SearchForMobileSubscriber-argument (SEQUENCE).
type SearchForMobileSubscriberArgument struct {
	Imsi               IMSI                                                `asn1:""`
	StoredLocationArea SearchForMobileSubscriberArgumentStoredLocationArea `asn1:""`
	berReplayNode_     *ber.ReplayNode                                     `asn1:"-" json:"-"`
}

// SendInfoForIncomingCallArgument represents the ASN.1 type SendInfoForIncomingCall-argument (SEQUENCE).
type SendInfoForIncomingCallArgument struct {
	IncomingId         SendInfoForIncomingCallArgumentIncomingId `asn1:""`
	BearerService      *BearerServiceCode                        `asn1:"tag:2,context,implicit,optional" json:"BearerService,omitempty"`
	Teleservice        *TeleserviceCode                          `asn1:"tag:3,context,implicit,optional" json:"Teleservice,omitempty"`
	LMsId              *LMsId                                    `asn1:"tag:4,context,implicit,optional" json:"LMsId,omitempty"`
	DialledNumber      *IsdnAddressString                        `asn1:"tag:5,context,implicit,optional" json:"DialledNumber,omitempty"`
	CugInterlock       *CUGInterlock                             `asn1:"tag:6,context,implicit,optional" json:"CugInterlock,omitempty"`
	NumberOfForwarding *NumberOfForwarding                       `asn1:"tag:7,context,implicit,optional" json:"NumberOfForwarding,omitempty"`
	berReplayNode_     *ber.ReplayNode                           `asn1:"-" json:"-"`
}

// SendInfoForOutgoingCallArgument represents the ASN.1 type SendInfoForOutgoingCall-argument (SEQUENCE).
type SendInfoForOutgoingCallArgument struct {
	CalledNumber   IsdnAddressString  `asn1:"tag:0,context,implicit"`
	BearerService  *BearerServiceCode `asn1:"tag:2,context,implicit,optional" json:"BearerService,omitempty"`
	TeleService    *TeleserviceCode   `asn1:"tag:3,context,implicit,optional" json:"TeleService,omitempty"`
	berReplayNode_ *ber.ReplayNode    `asn1:"-" json:"-"`
}

// SendParametersArgument represents the ASN.1 type SendParameters-argument (SEQUENCE).
type SendParametersArgument struct {
	SubscriberId               SubscriberId       `asn1:""`
	RequestParameters          *RequestParameters `asn1:""`
	berRequestParametersIndef_ bool               `asn1:"-" json:"-"`
	berReplayNode_             *ber.ReplayNode    `asn1:"-" json:"-"`
}

// SendRoutingInfoForSMArgument represents the ASN.1 type SendRoutingInfoForSM-argument (SEQUENCE).
type SendRoutingInfoForSMArgument struct {
	MsIsdn               IsdnAddressString `asn1:"tag:0,context,implicit"`
	SmRPPRI              bool              `asn1:"tag:1,context,implicit"`
	berSmRPPRIRaw_       byte              `asn1:"-" json:"-"`
	ServiceCentreAddress AddressString     `asn1:"tag:2,context,implicit"`
	CugInterlock         *CUGInterlock     `asn1:"tag:3,context,implicit,optional" json:"CugInterlock,omitempty"`
	TeleserviceCode      *TeleserviceCode  `asn1:"tag:5,context,implicit,optional" json:"TeleserviceCode,omitempty"`
	berReplayNode_       *ber.ReplayNode   `asn1:"-" json:"-"`
}

// SendRoutingInfoForSMResult represents the ASN.1 type SendRoutingInfoForSM-result (SEQUENCE).
type SendRoutingInfoForSMResult struct {
	Imsi IMSI `asn1:""`
	// Component1 is the anonymous component at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 20.1, 22.1.

	Component1     SendRoutingInfoForSMResultComponent1 `asn1:""`
	MwdSet         *bool                                `asn1:"tag:2,context,implicit,optional" json:"MwdSet,omitempty"`
	berMwdSetRaw_  byte                                 `asn1:"-" json:"-"`
	berReplayNode_ *ber.ReplayNode                      `asn1:"-" json:"-"`
}

// SendRoutingInformationArgument represents the ASN.1 type SendRoutingInformation-argument (SEQUENCE).
type SendRoutingInformationArgument struct {
	MsIsdn             IsdnAddressString   `asn1:"tag:0,context,implicit"`
	CugInterlock       *CUGInterlock       `asn1:"tag:1,context,implicit,optional" json:"CugInterlock,omitempty"`
	NumberOfForwarding *NumberOfForwarding `asn1:"tag:2,context,implicit,optional" json:"NumberOfForwarding,omitempty"`
	NetworkSignalInfo  *ExternalSignalInfo `asn1:"tag:10,context,implicit,optional" json:"NetworkSignalInfo,omitempty"`
	berReplayNode_     *ber.ReplayNode     `asn1:"-" json:"-"`
}

// SendRoutingInformationResult represents the ASN.1 type SendRoutingInformation-result (SEQUENCE).
type SendRoutingInformationResult struct {
	Imsi           IMSI                                    `asn1:""`
	RoutingInfo    SendRoutingInformationResultRoutingInfo `asn1:""`
	berReplayNode_ *ber.ReplayNode                         `asn1:"-" json:"-"`
}

// SetCipheringModeArgument represents the ASN.1 type SetCipheringMode-argument (SEQUENCE).
type SetCipheringModeArgument struct {
	CipheringMode  CipheringMode   `asn1:""`
	Kc             *Kc             `asn1:",optional" json:"Kc,omitempty"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SetMessageWaitingDataArgument represents the ASN.1 type SetMessageWaitingData-argument (SEQUENCE).
type SetMessageWaitingDataArgument struct {
	MsIsdn               IsdnAddressString `asn1:""`
	ServiceCentreAddress AddressString     `asn1:""`
	berReplayNode_       *ber.ReplayNode   `asn1:"-" json:"-"`
}

// TraceSubscriberActivityArgument represents the ASN.1 type TraceSubscriberActivity-argument (SEQUENCE).
type TraceSubscriberActivityArgument struct {
	Imsi           *IMSI           `asn1:"tag:0,context,implicit,optional" json:"Imsi,omitempty"`
	TraceReference TraceReference  `asn1:"tag:1,context,implicit"`
	TraceType      TraceType       `asn1:"tag:2,context,implicit"`
	OmcId          *AddressString  `asn1:"tag:3,context,implicit,optional" json:"OmcId,omitempty"`
	CallReference  *CallReference  `asn1:"tag:4,context,implicit,optional" json:"CallReference,omitempty"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// UpdateLocationArgument represents the ASN.1 type UpdateLocation-argument (SEQUENCE).
type UpdateLocationArgument struct {
	Imsi           IMSI              `asn1:""`
	LocationInfo   LocationInfo      `asn1:""`
	VlrNumber      IsdnAddressString `asn1:""`
	LmsId          *LMsId            `asn1:"tag:10,context,implicit,optional" json:"LmsId,omitempty"`
	berReplayNode_ *ber.ReplayNode   `asn1:"-" json:"-"`
}

// UpdateLocationAreaArgument represents the ASN.1 type UpdateLocationArea-argument (SEQUENCE).
type UpdateLocationAreaArgument struct {
	SubscriberId      SubscriberId                                `asn1:""`
	PreviousLocAreaId UpdateLocationAreaArgumentPreviousLocAreaId `asn1:""`
	TargetLocAreaId   LocAreaId                                   `asn1:""`
	Cksn              CKSN                                        `asn1:""`
	berReplayNode_    *ber.ReplayNode                             `asn1:"-" json:"-"`
}

// CancelLocationArgumentAlternative1 is lifted from an anonymous NamedType at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 20.1, 22.1, 24.1.

// CancelLocationArgumentAlternative1 represents the ASN.1 type CancelLocation-argument-alternative1 (SEQUENCE).
type CancelLocationArgumentAlternative1 struct {
	Imsi           IMSI            `asn1:""`
	LMsId          LMsId           `asn1:""`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SearchForMobileSubscriberArgumentStoredLocationArea choice constants.
const (
	// SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative0 selects the anonymous alternative at zero-based position 0; X.208 (11/1988) §§12.5–12.6, 24.1.
	SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative0 = 1
	// SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative1 selects the anonymous alternative at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 24.1.
	SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative1 = 2
)

// SearchForMobileSubscriberArgumentStoredLocationArea represents the ASN.1 CHOICE type SearchForMobileSubscriber-argument-storedLocationArea.
type SearchForMobileSubscriberArgumentStoredLocationArea struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	// Alternative0 is the anonymous alternative at zero-based position 0; X.208 (11/1988) §§12.5–12.6, 24.1.
	Alternative0 *LocAreaId `json:"Alternative0,omitempty"`
	// Alternative1 is the anonymous alternative at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 24.1.
	Alternative1 *struct{} `json:"Alternative1,omitempty"`
}

// NewSearchForMobileSubscriberArgumentStoredLocationAreaAlternative0 creates a SearchForMobileSubscriberArgumentStoredLocationArea with the alternative0 alternative.
func NewSearchForMobileSubscriberArgumentStoredLocationAreaAlternative0(v LocAreaId) SearchForMobileSubscriberArgumentStoredLocationArea {
	return SearchForMobileSubscriberArgumentStoredLocationArea{
		Choice:       SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative0,
		Alternative0: &v,
	}
}

// NewSearchForMobileSubscriberArgumentStoredLocationAreaAlternative1 creates a SearchForMobileSubscriberArgumentStoredLocationArea with the alternative1 alternative.
func NewSearchForMobileSubscriberArgumentStoredLocationAreaAlternative1(v struct{}) SearchForMobileSubscriberArgumentStoredLocationArea {
	return SearchForMobileSubscriberArgumentStoredLocationArea{
		Choice:       SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative1,
		Alternative1: &v,
	}
}

// SendInfoForIncomingCallArgumentIncomingId choice constants.
const (
	SendInfoForIncomingCallArgumentIncomingIdChoiceRoamingNumber = 1
	SendInfoForIncomingCallArgumentIncomingIdChoiceImsi          = 2
)

// SendInfoForIncomingCallArgumentIncomingId represents the ASN.1 CHOICE type SendInfoForIncomingCall-argument-incomingId.
type SendInfoForIncomingCallArgumentIncomingId struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode    `json:"-"`
	RoamingNumber  *IsdnAddressString `json:"RoamingNumber,omitempty"`
	Imsi           *IMSI              `json:"Imsi,omitempty"`
}

// NewSendInfoForIncomingCallArgumentIncomingIdRoamingNumber creates a SendInfoForIncomingCallArgumentIncomingId with the roamingNumber alternative.
func NewSendInfoForIncomingCallArgumentIncomingIdRoamingNumber(v IsdnAddressString) SendInfoForIncomingCallArgumentIncomingId {
	return SendInfoForIncomingCallArgumentIncomingId{
		Choice:        SendInfoForIncomingCallArgumentIncomingIdChoiceRoamingNumber,
		RoamingNumber: &v,
	}
}

// NewSendInfoForIncomingCallArgumentIncomingIdImsi creates a SendInfoForIncomingCallArgumentIncomingId with the imsi alternative.
func NewSendInfoForIncomingCallArgumentIncomingIdImsi(v IMSI) SendInfoForIncomingCallArgumentIncomingId {
	return SendInfoForIncomingCallArgumentIncomingId{
		Choice: SendInfoForIncomingCallArgumentIncomingIdChoiceImsi,
		Imsi:   &v,
	}
}

// SendRoutingInfoForSMResultComponent1 is lifted from an anonymous NamedType at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 20.1, 22.1, 24.1.

// SendRoutingInfoForSMResultComponent1 choice constants.
const (
	// SendRoutingInfoForSMResultComponent1ChoiceAlternative0 selects the anonymous alternative at zero-based position 0; X.208 (11/1988) §§12.5–12.6, 24.1.
	SendRoutingInfoForSMResultComponent1ChoiceAlternative0   = 1
	SendRoutingInfoForSMResultComponent1ChoiceForwardingData = 2
)

// SendRoutingInfoForSMResultComponent1 represents the ASN.1 CHOICE type SendRoutingInfoForSM-result-component1.
type SendRoutingInfoForSMResultComponent1 struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	// Alternative0 is the anonymous alternative at zero-based position 0; X.208 (11/1988) §§12.5–12.6, 24.1.
	Alternative0   *SendRoutingInfoForSMResultComponent1Alternative0 `json:"Alternative0,omitempty"`
	ForwardingData *ForwardingData                                   `json:"ForwardingData,omitempty"`
}

// NewSendRoutingInfoForSMResultComponent1Alternative0 creates a SendRoutingInfoForSMResultComponent1 with the alternative0 alternative.
func NewSendRoutingInfoForSMResultComponent1Alternative0(v SendRoutingInfoForSMResultComponent1Alternative0) SendRoutingInfoForSMResultComponent1 {
	return SendRoutingInfoForSMResultComponent1{
		Choice:       SendRoutingInfoForSMResultComponent1ChoiceAlternative0,
		Alternative0: &v,
	}
}

// NewSendRoutingInfoForSMResultComponent1ForwardingData creates a SendRoutingInfoForSMResultComponent1 with the forwardingData alternative.
func NewSendRoutingInfoForSMResultComponent1ForwardingData(v ForwardingData) SendRoutingInfoForSMResultComponent1 {
	return SendRoutingInfoForSMResultComponent1{
		Choice:         SendRoutingInfoForSMResultComponent1ChoiceForwardingData,
		ForwardingData: &v,
	}
}

// SendRoutingInfoForSMResultComponent1Alternative0 is lifted from an anonymous NamedType at zero-based position 0; X.208 (11/1988) §§12.5–12.6, 20.1, 22.1, 24.1.

// SendRoutingInfoForSMResultComponent1Alternative0 represents the ASN.1 type SendRoutingInfoForSM-result-component1-alternative0 (SEQUENCE).
type SendRoutingInfoForSMResultComponent1Alternative0 struct {
	LocationInfo   LocationInfo    `asn1:""`
	LMsId          *LMsId          `asn1:",optional" json:"LMsId,omitempty"`
	berReplayNode_ *ber.ReplayNode `asn1:"-" json:"-"`
}

// SendRoutingInformationResultRoutingInfo choice constants.
const (
	SendRoutingInformationResultRoutingInfoChoiceRoamingNumber  = 1
	SendRoutingInformationResultRoutingInfoChoiceForwardingData = 2
)

// SendRoutingInformationResultRoutingInfo represents the ASN.1 CHOICE type SendRoutingInformation-result-routingInfo.
type SendRoutingInformationResultRoutingInfo struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode    `json:"-"`
	RoamingNumber  *IsdnAddressString `json:"RoamingNumber,omitempty"`
	ForwardingData *ForwardingData    `json:"ForwardingData,omitempty"`
}

// NewSendRoutingInformationResultRoutingInfoRoamingNumber creates a SendRoutingInformationResultRoutingInfo with the roamingNumber alternative.
func NewSendRoutingInformationResultRoutingInfoRoamingNumber(v IsdnAddressString) SendRoutingInformationResultRoutingInfo {
	return SendRoutingInformationResultRoutingInfo{
		Choice:        SendRoutingInformationResultRoutingInfoChoiceRoamingNumber,
		RoamingNumber: &v,
	}
}

// NewSendRoutingInformationResultRoutingInfoForwardingData creates a SendRoutingInformationResultRoutingInfo with the forwardingData alternative.
func NewSendRoutingInformationResultRoutingInfoForwardingData(v ForwardingData) SendRoutingInformationResultRoutingInfo {
	return SendRoutingInformationResultRoutingInfo{
		Choice:         SendRoutingInformationResultRoutingInfoChoiceForwardingData,
		ForwardingData: &v,
	}
}

// UpdateLocationAreaArgumentPreviousLocAreaId choice constants.
const (
	// UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative0 selects the anonymous alternative at zero-based position 0; X.208 (11/1988) §§12.5–12.6, 24.1.
	UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative0 = 1
	// UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative1 selects the anonymous alternative at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 24.1.
	UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative1 = 2
)

// UpdateLocationAreaArgumentPreviousLocAreaId represents the ASN.1 CHOICE type UpdateLocationArea-argument-previousLocAreaId.
type UpdateLocationAreaArgumentPreviousLocAreaId struct {
	Choice         int
	berReplayNode_ *ber.ReplayNode `json:"-"`
	// Alternative0 is the anonymous alternative at zero-based position 0; X.208 (11/1988) §§12.5–12.6, 24.1.
	Alternative0 *LocAreaId `json:"Alternative0,omitempty"`
	// Alternative1 is the anonymous alternative at zero-based position 1; X.208 (11/1988) §§12.5–12.6, 24.1.
	Alternative1 *struct{} `json:"Alternative1,omitempty"`
}

// NewUpdateLocationAreaArgumentPreviousLocAreaIdAlternative0 creates a UpdateLocationAreaArgumentPreviousLocAreaId with the alternative0 alternative.
func NewUpdateLocationAreaArgumentPreviousLocAreaIdAlternative0(v LocAreaId) UpdateLocationAreaArgumentPreviousLocAreaId {
	return UpdateLocationAreaArgumentPreviousLocAreaId{
		Choice:       UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative0,
		Alternative0: &v,
	}
}

// NewUpdateLocationAreaArgumentPreviousLocAreaIdAlternative1 creates a UpdateLocationAreaArgumentPreviousLocAreaId with the alternative1 alternative.
func NewUpdateLocationAreaArgumentPreviousLocAreaIdAlternative1(v struct{}) UpdateLocationAreaArgumentPreviousLocAreaId {
	return UpdateLocationAreaArgumentPreviousLocAreaId{
		Choice:       UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative1,
		Alternative1: &v,
	}
}

// MarshalBER encodes ActivateSSArgument to BER format.
func (v *ActivateSSArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ActivateSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ActivateSSArgument).MarshalBER, (*ActivateSSArgument).marshalBER, 3)

}
func (v *ActivateSSArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, sd78d83_0, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ActivateSSArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ActivateSSArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ActivateSSArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ActivateSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, sd78d83_0, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ActivateSSArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ActivateSSArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ActivateSSArgument from BER/DER format.
func (destination *ActivateSSArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ActivateSSArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(ActivateSSArgument)

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
			var probe ActivateSSArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_0, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ActivateSSArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ActivateSSArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ActivateSSArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ActivateSSArgument", Cause: ber.ErrExtraData}
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
			if constraintErr := checkDecodedLength(opts, sd78d83_0, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
					len(content) || n_basicservice < 0 || n_basicservice > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicService", "decoding", false)
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
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ActivateSSArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ActivateTraceModeArgument to BER format.
func (v *ActivateTraceModeArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ActivateTraceModeArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ActivateTraceModeArgument).MarshalBER, (*ActivateTraceModeArgument).marshalBER, 3)

}
func (v *ActivateTraceModeArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, sd78d83_1, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := checkEncodedLength(opts, sd78d83_1, "37.4", "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", false)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", false)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := checkEncodedValue(opts, sd78d83_1, "37.3", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", false)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_1, "37.4", "omcId", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_omcid, encodeErr_enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		if encodeErr_enc_omcid != nil {
			return nil, qualifyBERError(encodeErr_enc_omcid, "omcId", "encoding", false)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, qualifyBERError(tagErr_enc_omcid, "omcId", "encoding", false)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ActivateTraceModeArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ActivateTraceModeArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ActivateTraceModeArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ActivateTraceModeArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, sd78d83_1, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := checkEncodedLength(nil, sd78d83_1, "37.4", "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", true)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", true)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := checkEncodedValue(nil, sd78d83_1, "37.3", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", true)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_1, "37.4", "omcId", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_omcid, encodeErr_enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		if encodeErr_enc_omcid != nil {
			return nil, qualifyBERError(encodeErr_enc_omcid, "omcId", "encoding", true)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, qualifyBERError(tagErr_enc_omcid, "omcId", "encoding", true)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ActivateTraceModeArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ActivateTraceModeArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ActivateTraceModeArgument from BER/DER format.
func (destination *ActivateTraceModeArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ActivateTraceModeArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(ActivateTraceModeArgument)

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
			var probe ActivateTraceModeArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_1, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ActivateTraceModeArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ActivateTraceModeArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ActivateTraceModeArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ActivateTraceModeArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
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
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, sd78d83_1, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceReference
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field traceReference", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("%w: expected tag [%s %d] for traceReference, got %s", ber.ErrUnexpectedElement, "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "traceReference", content[offset:])
		decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceReference", "decoding", false)
		}
		if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tracereference), "traceReference", "decoding", false)
		}
		decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "traceReference", "decoding", false)
		}
		v.TraceReference = TraceReference(decVal_tracereference)
		if offset < 0 || offset >
			len(content) || n_tracereference < 0 || n_tracereference > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_tracereference
		if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
			if constraintErr := checkDecodedLength(opts, sd78d83_1, "37.4", "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode traceType
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field traceType", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("%w: expected tag [%s %d] for traceType, got %s", ber.ErrUnexpectedElement, "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "traceType", content[offset:])
		decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceType", "decoding", false)
		}
		if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 2 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tracetype), "traceType", "decoding", false)
		}
		if decodedTag_tracetype.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_tracetype), "traceType", "decoding", false)
		}
		decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
		if intErr != nil {
			return qualifyBERError(intErr, "traceType", "decoding", false)
		}
		v.TraceType = TraceType(decVal_tracetype)
		if offset < 0 || offset >
			len(content) || n_tracetype < 0 || n_tracetype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_tracetype
		if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
			if constraintErr := checkDecodedValue(opts, sd78d83_1, "37.3", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode omcId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "omcId", content[offset:])
				decodedTag_omcid, n_omcid, rawVal_omcid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "omcId", "decoding", false)
				}
				if decodedTag_omcid.Class != tag.ClassContextSpecific || decodedTag_omcid.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_omcid), "omcId", "decoding", false)
				}
				decVal_omcid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_omcid.Constructed, rawVal_omcid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "omcId", "decoding", false)
				}
				tmp_omcid := AddressString(decVal_omcid)
				v.OmcId = &tmp_omcid
				if offset < 0 || offset >
					len(content) || n_omcid < 0 || n_omcid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_omcid
				if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_1, "37.4", "omcId", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ActivateTraceModeArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes AlertServiceCentreArgument to BER format.
func (v *AlertServiceCentreArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: AlertServiceCentreArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*AlertServiceCentreArgument).MarshalBER, (*AlertServiceCentreArgument).marshalBER, 3)

}
func (v *AlertServiceCentreArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_2, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_2, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", false)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_2, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", false)
	}
	children = append(children, enc_servicecentreaddress...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *AlertServiceCentreArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes AlertServiceCentreArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *AlertServiceCentreArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AlertServiceCentreArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_2, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_2, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", true)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_2, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", true)
	}
	children = append(children, enc_servicecentreaddress...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AlertServiceCentreArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *AlertServiceCentreArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes AlertServiceCentreArgument from BER/DER format.
func (destination *AlertServiceCentreArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: AlertServiceCentreArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(AlertServiceCentreArgument)

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
			var probe AlertServiceCentreArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_2, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = AlertServiceCentreArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*AlertServiceCentreArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding AlertServiceCentreArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AlertServiceCentreArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msIsdn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field msIsdn", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "msIsdn", content[offset:])
		val_msisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msIsdn", "decoding", false)
		}
		v.MsIsdn = IsdnAddressString(val_msisdn)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_2, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_2, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
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
			if constraintErr := checkDecodedLength(opts, sd78d83_2, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AlertServiceCentreArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes AuthenticateArgument to BER format.
func (v *AuthenticateArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: AuthenticateArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*AuthenticateArgument).MarshalBER, (*AuthenticateArgument).marshalBER, 3)

}
func (v *AuthenticateArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := checkEncodedLength(opts, sd78d83_3, "37.4", "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_rand, encodeErr_enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	if encodeErr_enc_rand != nil {
		return nil, qualifyBERError(encodeErr_enc_rand, "rand", "encoding", false)
	}
	children = append(children, enc_rand...)
	if len(v.Cksn) < 1 || len(v.Cksn) > 1 {
		if constraintErr := checkEncodedLength(opts, sd78d83_3, "37.4", "cksn", "SIZE (1)", len(v.Cksn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cksn, encodeErr_enc_cksn := ber.EncodeOctetString([]byte(v.Cksn))
	if encodeErr_enc_cksn != nil {
		return nil, qualifyBERError(encodeErr_enc_cksn, "cksn", "encoding", false)
	}
	children = append(children, enc_cksn...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *AuthenticateArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes AuthenticateArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *AuthenticateArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: AuthenticateArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Rand) < 16 || len(v.Rand) > 16 {
		if constraintErr := checkEncodedLength(nil, sd78d83_3, "37.4", "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_rand, encodeErr_enc_rand := ber.EncodeOctetString([]byte(v.Rand))
	if encodeErr_enc_rand != nil {
		return nil, qualifyBERError(encodeErr_enc_rand, "rand", "encoding", true)
	}
	children = append(children, enc_rand...)
	if len(v.Cksn) < 1 || len(v.Cksn) > 1 {
		if constraintErr := checkEncodedLength(nil, sd78d83_3, "37.4", "cksn", "SIZE (1)", len(v.Cksn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cksn, encodeErr_enc_cksn := ber.EncodeOctetString([]byte(v.Cksn))
	if encodeErr_enc_cksn != nil {
		return nil, qualifyBERError(encodeErr_enc_cksn, "cksn", "encoding", true)
	}
	children = append(children, enc_cksn...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding AuthenticateArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *AuthenticateArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes AuthenticateArgument from BER/DER format.
func (destination *AuthenticateArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: AuthenticateArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(AuthenticateArgument)

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
			var probe AuthenticateArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_3, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = AuthenticateArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*AuthenticateArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding AuthenticateArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "AuthenticateArgument", Cause: ber.ErrExtraData}
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
			if constraintErr := checkDecodedLength(opts, sd78d83_3, "37.4", "rand", "SIZE (16)", len(v.Rand)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cksn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cksn", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cksn", content[offset:])
		val_cksn, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cksn", "decoding", false)
		}
		v.Cksn = CKSN(val_cksn)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Cksn) < 1 || len(v.Cksn) > 1 {
			if constraintErr := checkDecodedLength(opts, sd78d83_3, "37.4", "cksn", "SIZE (1)", len(v.Cksn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "AuthenticateArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes BeginSubscriberActivityArgument to BER format.
func (v *BeginSubscriberActivityArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: BeginSubscriberActivityArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*BeginSubscriberActivityArgument).MarshalBER, (*BeginSubscriberActivityArgument).marshalBER, 3)

}
func (v *BeginSubscriberActivityArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, sd78d83_4, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_4, "37.4", "originatingEntityNumber", "SIZE (1..10)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_4, "37.4", "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
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
func (v *BeginSubscriberActivityArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes BeginSubscriberActivityArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *BeginSubscriberActivityArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: BeginSubscriberActivityArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, sd78d83_4, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_4, "37.4", "originatingEntityNumber", "SIZE (1..10)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_4, "37.4", "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding BeginSubscriberActivityArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *BeginSubscriberActivityArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes BeginSubscriberActivityArgument from BER/DER format.
func (destination *BeginSubscriberActivityArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: BeginSubscriberActivityArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(BeginSubscriberActivityArgument)

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
			var probe BeginSubscriberActivityArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_4, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = BeginSubscriberActivityArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*BeginSubscriberActivityArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding BeginSubscriberActivityArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "BeginSubscriberActivityArgument", Cause: ber.ErrExtraData}
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
		if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, sd78d83_4, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
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
		v.OriginatingEntityNumber = IsdnAddressString(val_originatingentitynumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_4, "37.4", "originatingEntityNumber", "SIZE (1..10)", len(v.OriginatingEntityNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_4, "37.4", "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "BeginSubscriberActivityArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes CancelLocationArgument to BER format.
func (v *CancelLocationArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CancelLocationArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CancelLocationArgument).MarshalBER, (*CancelLocationArgument).marshalBER, 3)

}
func (v *CancelLocationArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *CancelLocationArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case CancelLocationArgumentChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice CancelLocationArgument: imsi is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, "MAP-Operations.CancelLocation-argument", "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case CancelLocationArgumentChoiceAlternative1:
		if v.Alternative1 == nil {
			return nil, fmt.Errorf("%w: choice CancelLocationArgument: alternative1 is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.Alternative1.MarshalBER(ber.ChildEncodeOptions(opts, "alternative1")...)
		if err != nil {
			return nil, qualifyBERError(err, "alternative1", "encoding", false)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for CancelLocationArgument", v.Choice)
	}
}

// MarshalDER encodes CancelLocationArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CancelLocationArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CancelLocationArgument receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case CancelLocationArgumentChoiceAlternative1:
		if v.Alternative1 == nil {
			return nil, fmt.Errorf("%w: choice CancelLocationArgument: alternative1 is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.Alternative1.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "alternative1", "encoding", true)
		}
		if derErr := ber.ValidateDEREncodedElement(enc_der_1); derErr != nil {
			return nil, qualifyBERError(derErr, "alternative1", "encoding", true)
		}
		return enc_der_1, nil
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case CancelLocationArgumentChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		case CancelLocationArgumentChoiceAlternative1:
			return nil, qualifyBERError(err, "alternative1", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding CancelLocationArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *CancelLocationArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CancelLocationArgument from BER/DER format.
func (destination *CancelLocationArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CancelLocationArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(CancelLocationArgument)

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
				opts, v, &v.berReplayNode_, (*CancelLocationArgument).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe CancelLocationArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-Operations.CancelLocation-argument", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CancelLocationArgument{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for CancelLocationArgument CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for CancelLocationArgument: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding CancelLocationArgument CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelLocationArgument", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "CancelLocationArgument.alternative1", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = CancelLocationArgumentChoiceImsi
		ber.MarkPreflightTarget(opts, "imsi", choiceData)
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return qualifyBERError(osErr, "imsi", "decoding", false)
		}
		tmp := IMSI(decVal)
		v.Imsi = &tmp
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, "MAP-Operations.CancelLocation-argument", "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = CancelLocationArgumentChoiceAlternative1
		ber.MarkPreflightTarget(opts, "alternative1", choiceData)
		var dec CancelLocationArgumentAlternative1
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "alternative1")...); unmErr != nil {
			return qualifyBERError(unmErr, "alternative1", "decoding", false)
		}
		v.Alternative1 = &dec
	} else {
		return fmt.Errorf("%w: unknown tag %s for CancelLocationArgument CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes CompleteCallArgument to BER format.
func (v *CompleteCallArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CompleteCallArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CompleteCallArgument).MarshalBER, (*CompleteCallArgument).marshalBER, 3)

}
func (v *CompleteCallArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_5, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_5, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", false)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msIsdn", "encoding", false)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_5, "37.4", "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, qualifyBERError(encodeErr_enc_category, "category", "encoding", false)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_category)
		if tagErr_enc_category != nil {
			return nil, qualifyBERError(tagErr_enc_category, "category", "encoding", false)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.CugIndex != nil {
		if len(*v.CugIndex) < 1 || len(*v.CugIndex) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_5, "37.4", "cug-Index", "SIZE (1)", len(*v.CugIndex)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cugindex, encodeErr_enc_cugindex := ber.EncodeOctetString([]byte(*v.CugIndex))
		if encodeErr_enc_cugindex != nil {
			return nil, qualifyBERError(encodeErr_enc_cugindex, "cug-Index", "encoding", false)
		}
		retagged_enc_cugindex, tagErr_enc_cugindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_cugindex)
		if tagErr_enc_cugindex != nil {
			return nil, qualifyBERError(tagErr_enc_cugindex, "cug-Index", "encoding", false)
		}
		enc_cugindex = retagged_enc_cugindex
		children = append(children, enc_cugindex...)
	}
	if v.GSMBearerCapability != nil {
		enc_gsmbearercapability, err := v.GSMBearerCapability.MarshalBER(ber.ChildEncodeOptions(opts, "gSM-BearerCapability")...)
		if err != nil {
			return nil, qualifyBERError(err, "gSM-BearerCapability", "encoding", false)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, qualifyBERError(tagErr_enc_gsmbearercapability, "gSM-BearerCapability", "encoding", false)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_gsmbearercapability)
		children = append(children, enc_gsmbearercapability...)
	}
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := checkEncodedValue(opts, sd78d83_5, "37.3", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		retagged_enc_noreplyconditiontime, tagErr_enc_noreplyconditiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_noreplyconditiontime)
		if tagErr_enc_noreplyconditiontime != nil {
			return nil, qualifyBERError(tagErr_enc_noreplyconditiontime, "noReplyConditionTime", "encoding", false)
		}
		enc_noreplyconditiontime = retagged_enc_noreplyconditiontime
		children = append(children, enc_noreplyconditiontime...)
	}
	if v.SsDataList != nil {
		if len((v.SsDataList).Values) < 1 || len((v.SsDataList).Values) > 30 {
			if constraintErr := checkEncodedLength(opts, sd78d83_5, "37.4", "ss-DataList", "SIZE (1..30)", len((v.SsDataList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssdatalist, err := MarshalBERSSDataList(v.SsDataList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "ss-DataList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "ss-DataList", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berSsDataListIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_ssdatalist)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_ssdatalist, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 5}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "ss-DataList", "encoding", false)
				}
			}
		} else {
			retagged_enc_ssdatalist, tagErr_enc_ssdatalist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ssdatalist)
			if tagErr_enc_ssdatalist != nil {
				return nil, qualifyBERError(tagErr_enc_ssdatalist, "ss-DataList", "encoding", false)
			}
			enc_ssdatalist = retagged_enc_ssdatalist
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_ssdatalist)
		children = append(children, enc_ssdatalist...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CompleteCallArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CompleteCallArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CompleteCallArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CompleteCallArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_5, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_5, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", true)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msIsdn", "encoding", true)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if v.Category != nil {
		if len(*v.Category) < 1 || len(*v.Category) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_5, "37.4", "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_category, encodeErr_enc_category := ber.EncodeOctetString([]byte(*v.Category))
		if encodeErr_enc_category != nil {
			return nil, qualifyBERError(encodeErr_enc_category, "category", "encoding", true)
		}
		retagged_enc_category, tagErr_enc_category := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_category)
		if tagErr_enc_category != nil {
			return nil, qualifyBERError(tagErr_enc_category, "category", "encoding", true)
		}
		enc_category = retagged_enc_category
		children = append(children, enc_category...)
	}
	if v.CugIndex != nil {
		if len(*v.CugIndex) < 1 || len(*v.CugIndex) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_5, "37.4", "cug-Index", "SIZE (1)", len(*v.CugIndex)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cugindex, encodeErr_enc_cugindex := ber.EncodeOctetString([]byte(*v.CugIndex))
		if encodeErr_enc_cugindex != nil {
			return nil, qualifyBERError(encodeErr_enc_cugindex, "cug-Index", "encoding", true)
		}
		retagged_enc_cugindex, tagErr_enc_cugindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_cugindex)
		if tagErr_enc_cugindex != nil {
			return nil, qualifyBERError(tagErr_enc_cugindex, "cug-Index", "encoding", true)
		}
		enc_cugindex = retagged_enc_cugindex
		children = append(children, enc_cugindex...)
	}
	if v.GSMBearerCapability != nil {
		enc_gsmbearercapability, err := v.GSMBearerCapability.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "gSM-BearerCapability", "encoding", true)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, qualifyBERError(tagErr_enc_gsmbearercapability, "gSM-BearerCapability", "encoding", true)
		}
		enc_gsmbearercapability = retagged_enc_gsmbearercapability
		children = append(children, enc_gsmbearercapability...)
	}
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := checkEncodedValue(nil, sd78d83_5, "37.3", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_noreplyconditiontime := ber.EncodeInteger(int64(*v.NoReplyConditionTime))
		retagged_enc_noreplyconditiontime, tagErr_enc_noreplyconditiontime := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_noreplyconditiontime)
		if tagErr_enc_noreplyconditiontime != nil {
			return nil, qualifyBERError(tagErr_enc_noreplyconditiontime, "noReplyConditionTime", "encoding", true)
		}
		enc_noreplyconditiontime = retagged_enc_noreplyconditiontime
		children = append(children, enc_noreplyconditiontime...)
	}
	if v.SsDataList != nil {
		if len((v.SsDataList).Values) < 1 || len((v.SsDataList).Values) > 30 {
			if constraintErr := checkEncodedLength(nil, sd78d83_5, "37.4", "ss-DataList", "SIZE (1..30)", len((v.SsDataList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssdatalist, err := MarshalDERSSDataList(v.SsDataList)
		if err != nil {
			return nil, qualifyBERError(err, "ss-DataList", "encoding", true)
		}
		retagged_enc_ssdatalist, tagErr_enc_ssdatalist := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ssdatalist)
		if tagErr_enc_ssdatalist != nil {
			return nil, qualifyBERError(tagErr_enc_ssdatalist, "ss-DataList", "encoding", true)
		}
		enc_ssdatalist = retagged_enc_ssdatalist
		children = append(children, enc_ssdatalist...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding CompleteCallArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CompleteCallArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CompleteCallArgument from BER/DER format.
func (destination *CompleteCallArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CompleteCallArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(CompleteCallArgument)

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
			var probe CompleteCallArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_5, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CompleteCallArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CompleteCallArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CompleteCallArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CompleteCallArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msIsdn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field msIsdn", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("%w: expected tag [%s %d] for msIsdn, got %s", ber.ErrUnexpectedElement, "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "msIsdn", content[offset:])
		decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msIsdn", "decoding", false)
		}
		if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_msisdn), "msIsdn", "decoding", false)
		}
		decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msIsdn", "decoding", false)
		}
		v.MsIsdn = IsdnAddressString(decVal_msisdn)
		if offset > len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_msisdn
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_5, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_5, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode category
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "category", content[offset:])
				decodedTag_category, n_category, rawVal_category, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "category", "decoding", false)
				}
				if decodedTag_category.Class != tag.ClassContextSpecific || decodedTag_category.Number != 1 {
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
					if constraintErr := checkDecodedLength(opts, sd78d83_5, "37.4", "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cug-Index
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "cug-Index", content[offset:])
				decodedTag_cugindex, n_cugindex, rawVal_cugindex, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cug-Index", "decoding", false)
				}
				if decodedTag_cugindex.Class != tag.ClassContextSpecific || decodedTag_cugindex.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_cugindex), "cug-Index", "decoding", false)
				}
				decVal_cugindex, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cugindex.Constructed, rawVal_cugindex, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "cug-Index", "decoding", false)
				}
				tmp_cugindex := CUGIndex(decVal_cugindex)
				v.CugIndex = &tmp_cugindex
				if offset < 0 || offset >
					len(content) || n_cugindex < 0 || n_cugindex > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugindex
				if len(*v.CugIndex) < 1 || len(*v.CugIndex) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_5, "37.4", "cug-Index", "SIZE (1)", len(*v.CugIndex)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode gSM-BearerCapability
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "gSM-BearerCapability", content[offset:])
				decodedTag_gsmbearercapability, n_gsmbearercapability, rawVal_gsmbearercapability, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "gSM-BearerCapability", "decoding", false)
				}
				if decodedTag_gsmbearercapability.Class != tag.ClassContextSpecific || decodedTag_gsmbearercapability.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_gsmbearercapability), "gSM-BearerCapability", "decoding", false)
				}
				if decodedTag_gsmbearercapability.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_gsmbearercapability), "gSM-BearerCapability", "decoding", false)
				}
				_ = rawVal_gsmbearercapability
				if offset < 0 || offset >
					len(content) || n_gsmbearercapability < 0 || n_gsmbearercapability >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_gsmbearercapability, reconstructionErr_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_gsmbearercapability])
				if reconstructionErr_gsmbearercapability != nil {
					return qualifyBERError(reconstructionErr_gsmbearercapability, "gSM-BearerCapability", "decoding", false)
				}
				var dec_gsmbearercapability ExternalSignalInfo
				if unmErr := dec_gsmbearercapability.UnmarshalBER(reconstructed_gsmbearercapability, ber.ChildDecodeOptions(opts, "gSM-BearerCapability")...); unmErr != nil {
					return qualifyBERError(unmErr, "gSM-BearerCapability", "decoding", false)
				}
				v.GSMBearerCapability = &dec_gsmbearercapability
				if offset < 0 || offset >
					len(content) || n_gsmbearercapability < 0 || n_gsmbearercapability >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_gsmbearercapability
			}
		}
	}
	// Decode noReplyConditionTime
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "noReplyConditionTime", content[offset:])
				decodedTag_noreplyconditiontime, n_noreplyconditiontime, rawVal_noreplyconditiontime, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "noReplyConditionTime", "decoding", false)
				}
				if decodedTag_noreplyconditiontime.Class != tag.ClassContextSpecific || decodedTag_noreplyconditiontime.Number != 4 {
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
					if constraintErr := checkDecodedValue(opts, sd78d83_5, "37.3", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ss-DataList
	v.berSsDataListIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "ss-DataList", content[offset:])
				decodedTag_ssdatalist, n_ssdatalist, rawVal_ssdatalist, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-DataList", "decoding", false)
				}
				if decodedTag_ssdatalist.Class != tag.ClassContextSpecific || decodedTag_ssdatalist.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_ssdatalist), "ss-DataList", "decoding", false)
				}
				if decodedTag_ssdatalist.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_ssdatalist), "ss-DataList", "decoding", false)
				}
				_ = rawVal_ssdatalist
				if offset < 0 || offset >
					len(content) || n_ssdatalist < 0 || n_ssdatalist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_ssdatalist, reconstructionErr_ssdatalist := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_ssdatalist])
				if reconstructionErr_ssdatalist != nil {
					return qualifyBERError(reconstructionErr_ssdatalist, "ss-DataList", "decoding", false)
				}
				dec_ssdatalist, unmErr := UnmarshalBERSSDataList(reconstructed_ssdatalist, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "ss-DataList"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "ss-DataList", "decoding", false)
				}
				v.SsDataList = dec_ssdatalist
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berSsDataListIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_ssdatalist < 0 || n_ssdatalist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssdatalist
				if len((v.SsDataList).Values) < 1 || len((v.SsDataList).Values) > 30 {
					if constraintErr := checkDecodedLength(opts, sd78d83_5, "37.4", "ss-DataList", "SIZE (1..30)", len((v.SsDataList).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CompleteCallArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ConnectToFollowingAddressArgument to BER format.
func (v *ConnectToFollowingAddressArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ConnectToFollowingAddressArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ConnectToFollowingAddressArgument).MarshalBER, (*ConnectToFollowingAddressArgument).marshalBER, 3)

}
func (v *ConnectToFollowingAddressArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_forwardingdata, err := v.ForwardingData.MarshalBER(ber.ChildEncodeOptions(opts, "forwardingData")...)
	if err != nil {
		return nil, qualifyBERError(err, "forwardingData", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_forwardingdata)
	children = append(children, enc_forwardingdata...)
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_6, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_6, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.MsIsdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", false)
		}
		children = append(children, enc_msisdn...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ConnectToFollowingAddressArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ConnectToFollowingAddressArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ConnectToFollowingAddressArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ConnectToFollowingAddressArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_forwardingdata, err := v.ForwardingData.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "forwardingData", "encoding", true)
	}
	children = append(children, enc_forwardingdata...)
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkEncodedLength(nil, sd78d83_6, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_6, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.MsIsdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", true)
		}
		children = append(children, enc_msisdn...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ConnectToFollowingAddressArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ConnectToFollowingAddressArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ConnectToFollowingAddressArgument from BER/DER format.
func (destination *ConnectToFollowingAddressArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ConnectToFollowingAddressArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(ConnectToFollowingAddressArgument)

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
			var probe ConnectToFollowingAddressArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_6, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ConnectToFollowingAddressArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ConnectToFollowingAddressArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ConnectToFollowingAddressArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ConnectToFollowingAddressArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode forwardingData
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field forwardingData", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "forwardingData", content[offset:])
		// Decode nested SEQUENCE (ForwardingData)
		_, n_forwardingdata, _, tlvErr_forwardingdata := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_forwardingdata != nil {
			return qualifyBERError(tlvErr_forwardingdata, "forwardingData", "decoding", false)
		}
		if offset > len(content) || n_forwardingdata < 0 || n_forwardingdata > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.ForwardingData.UnmarshalBER(content[offset:offset+n_forwardingdata], ber.ChildDecodeOptions(opts, "forwardingData")...); unmErr != nil {
			return qualifyBERError(unmErr, "forwardingData", "decoding", false)
		}
		if offset > len(content) || n_forwardingdata < 0 || n_forwardingdata > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_forwardingdata
	}
	// Decode msIsdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "msIsdn", content[offset:])
				val_msisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msIsdn", "decoding", false)
				}
				tmp_msisdn := IsdnAddressString(val_msisdn)
				v.MsIsdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
					if constraintErr := checkDecodedLength(opts, sd78d83_6, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_6, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ConnectToFollowingAddressArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes DeactivateSSArgument to BER format.
func (v *DeactivateSSArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: DeactivateSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*DeactivateSSArgument).MarshalBER, (*DeactivateSSArgument).marshalBER, 3)

}
func (v *DeactivateSSArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, sd78d83_7, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *DeactivateSSArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes DeactivateSSArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *DeactivateSSArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DeactivateSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, sd78d83_7, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding DeactivateSSArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *DeactivateSSArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes DeactivateSSArgument from BER/DER format.
func (destination *DeactivateSSArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: DeactivateSSArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(DeactivateSSArgument)

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
			var probe DeactivateSSArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_7, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = DeactivateSSArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*DeactivateSSArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding DeactivateSSArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeactivateSSArgument", Cause: ber.ErrExtraData}
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
			if constraintErr := checkDecodedLength(opts, sd78d83_7, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DeactivateSSArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes DeactivateTraceModeArgument to BER format.
func (v *DeactivateTraceModeArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: DeactivateTraceModeArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*DeactivateTraceModeArgument).MarshalBER, (*DeactivateTraceModeArgument).marshalBER, 3)

}
func (v *DeactivateTraceModeArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, sd78d83_8, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := checkEncodedLength(opts, sd78d83_8, "37.4", "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", false)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", false)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *DeactivateTraceModeArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes DeactivateTraceModeArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *DeactivateTraceModeArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DeactivateTraceModeArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, sd78d83_8, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := checkEncodedLength(nil, sd78d83_8, "37.4", "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", true)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", true)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding DeactivateTraceModeArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *DeactivateTraceModeArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes DeactivateTraceModeArgument from BER/DER format.
func (destination *DeactivateTraceModeArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: DeactivateTraceModeArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(DeactivateTraceModeArgument)

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
			var probe DeactivateTraceModeArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_8, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = DeactivateTraceModeArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*DeactivateTraceModeArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding DeactivateTraceModeArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeactivateTraceModeArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
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
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, sd78d83_8, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceReference
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field traceReference", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("%w: expected tag [%s %d] for traceReference, got %s", ber.ErrUnexpectedElement, "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "traceReference", content[offset:])
		decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceReference", "decoding", false)
		}
		if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tracereference), "traceReference", "decoding", false)
		}
		decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "traceReference", "decoding", false)
		}
		v.TraceReference = TraceReference(decVal_tracereference)
		if offset < 0 || offset >
			len(content) || n_tracereference < 0 || n_tracereference > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_tracereference
		if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
			if constraintErr := checkDecodedLength(opts, sd78d83_8, "37.4", "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DeactivateTraceModeArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes DeleteSubscriberDataArgument to BER format.
func (v *DeleteSubscriberDataArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: DeleteSubscriberDataArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*DeleteSubscriberDataArgument).MarshalBER, (*DeleteSubscriberDataArgument).marshalBER, 3)

}
func (v *DeleteSubscriberDataArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, sd78d83_9, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
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
	if v.BasicService != nil {
		if len((v.BasicService).Values) < 1 || len((v.BasicService).Values) > 70 {
			if constraintErr := checkEncodedLength(opts, sd78d83_9, "37.4", "basicService", "SIZE (1..70)", len((v.BasicService).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservice, err := MarshalBERBasicServiceList(v.BasicService, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "basicService"))...)
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berBasicServiceIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_basicservice)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_basicservice, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 1}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "basicService", "encoding", false)
				}
			}
		} else {
			retagged_enc_basicservice, tagErr_enc_basicservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_basicservice)
			if tagErr_enc_basicservice != nil {
				return nil, qualifyBERError(tagErr_enc_basicservice, "basicService", "encoding", false)
			}
			enc_basicservice = retagged_enc_basicservice
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_basicservice)
		children = append(children, enc_basicservice...)
	}
	if v.SsCode != nil {
		if len((v.SsCode).Values) < 1 || len((v.SsCode).Values) > 30 {
			if constraintErr := checkEncodedLength(opts, sd78d83_9, "37.4", "ss-Code", "SIZE (1..30)", len((v.SsCode).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, err := MarshalBERSSCodeList(v.SsCode, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "ss-Code"))...)
		if err != nil {
			return nil, qualifyBERError(err, "ss-Code", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berSsCodeIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_sscode)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_sscode, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 2}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "ss-Code", "encoding", false)
				}
			}
		} else {
			retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sscode)
			if tagErr_enc_sscode != nil {
				return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", false)
			}
			enc_sscode = retagged_enc_sscode
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_sscode)
		children = append(children, enc_sscode...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *DeleteSubscriberDataArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes DeleteSubscriberDataArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *DeleteSubscriberDataArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: DeleteSubscriberDataArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, sd78d83_9, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
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
	if v.BasicService != nil {
		if len((v.BasicService).Values) < 1 || len((v.BasicService).Values) > 70 {
			if constraintErr := checkEncodedLength(nil, sd78d83_9, "37.4", "basicService", "SIZE (1..70)", len((v.BasicService).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_basicservice, err := MarshalDERBasicServiceList(v.BasicService)
		if err != nil {
			return nil, qualifyBERError(err, "basicService", "encoding", true)
		}
		retagged_enc_basicservice, tagErr_enc_basicservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_basicservice)
		if tagErr_enc_basicservice != nil {
			return nil, qualifyBERError(tagErr_enc_basicservice, "basicService", "encoding", true)
		}
		enc_basicservice = retagged_enc_basicservice
		children = append(children, enc_basicservice...)
	}
	if v.SsCode != nil {
		if len((v.SsCode).Values) < 1 || len((v.SsCode).Values) > 30 {
			if constraintErr := checkEncodedLength(nil, sd78d83_9, "37.4", "ss-Code", "SIZE (1..30)", len((v.SsCode).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, err := MarshalDERSSCodeList(v.SsCode)
		if err != nil {
			return nil, qualifyBERError(err, "ss-Code", "encoding", true)
		}
		retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_sscode)
		if tagErr_enc_sscode != nil {
			return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", true)
		}
		enc_sscode = retagged_enc_sscode
		children = append(children, enc_sscode...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding DeleteSubscriberDataArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *DeleteSubscriberDataArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes DeleteSubscriberDataArgument from BER/DER format.
func (destination *DeleteSubscriberDataArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: DeleteSubscriberDataArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(DeleteSubscriberDataArgument)

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
			var probe DeleteSubscriberDataArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_9, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = DeleteSubscriberDataArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*DeleteSubscriberDataArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding DeleteSubscriberDataArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "DeleteSubscriberDataArgument", Cause: ber.ErrExtraData}
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
		if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, sd78d83_9, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode basicService
	v.berBasicServiceIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "basicService", content[offset:])
				decodedTag_basicservice, n_basicservice, rawVal_basicservice, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "basicService", "decoding", false)
				}
				if decodedTag_basicservice.Class != tag.ClassContextSpecific || decodedTag_basicservice.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_basicservice), "basicService", "decoding", false)
				}
				if decodedTag_basicservice.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_basicservice), "basicService", "decoding", false)
				}
				_ = rawVal_basicservice
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_basicservice, reconstructionErr_basicservice := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_basicservice])
				if reconstructionErr_basicservice != nil {
					return qualifyBERError(reconstructionErr_basicservice, "basicService", "decoding", false)
				}
				dec_basicservice, unmErr := UnmarshalBERBasicServiceList(reconstructed_basicservice, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "basicService"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "basicService", "decoding", false)
				}
				v.BasicService = dec_basicservice
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berBasicServiceIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_basicservice < 0 || n_basicservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_basicservice
				if len((v.BasicService).Values) < 1 || len((v.BasicService).Values) > 70 {
					if constraintErr := checkDecodedLength(opts, sd78d83_9, "37.4", "basicService", "SIZE (1..70)", len((v.BasicService).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ss-Code
	v.berSsCodeIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "ss-Code", content[offset:])
				decodedTag_sscode, n_sscode, rawVal_sscode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Code", "decoding", false)
				}
				if decodedTag_sscode.Class != tag.ClassContextSpecific || decodedTag_sscode.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_sscode), "ss-Code", "decoding", false)
				}
				if decodedTag_sscode.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_sscode), "ss-Code", "decoding", false)
				}
				_ = rawVal_sscode
				if offset < 0 || offset >
					len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_sscode, reconstructionErr_sscode := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_sscode])
				if reconstructionErr_sscode != nil {
					return qualifyBERError(reconstructionErr_sscode, "ss-Code", "decoding", false)
				}
				dec_sscode, unmErr := UnmarshalBERSSCodeList(reconstructed_sscode, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "ss-Code"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "ss-Code", "decoding", false)
				}
				v.SsCode = dec_sscode
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berSsCodeIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sscode
				if len((v.SsCode).Values) < 1 || len((v.SsCode).Values) > 30 {
					if constraintErr := checkDecodedLength(opts, sd78d83_9, "37.4", "ss-Code", "SIZE (1..30)", len((v.SsCode).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "DeleteSubscriberDataArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes EraseSSArgument to BER format.
func (v *EraseSSArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: EraseSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*EraseSSArgument).MarshalBER, (*EraseSSArgument).marshalBER, 3)

}
func (v *EraseSSArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, sd78d83_10, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *EraseSSArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes EraseSSArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *EraseSSArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: EraseSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, sd78d83_10, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding EraseSSArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *EraseSSArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes EraseSSArgument from BER/DER format.
func (destination *EraseSSArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: EraseSSArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(EraseSSArgument)

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
			var probe EraseSSArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_10, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = EraseSSArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*EraseSSArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding EraseSSArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "EraseSSArgument", Cause: ber.ErrExtraData}
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
			if constraintErr := checkDecodedLength(opts, sd78d83_10, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "EraseSSArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ForwardShortMessageArgument to BER format.
func (v *ForwardShortMessageArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ForwardShortMessageArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ForwardShortMessageArgument).MarshalBER, (*ForwardShortMessageArgument).marshalBER, 3)

}
func (v *ForwardShortMessageArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
		if constraintErr := checkEncodedLength(opts, sd78d83_11, "37.4", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", false)
	}
	children = append(children, enc_smrpui...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ForwardShortMessageArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ForwardShortMessageArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ForwardShortMessageArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardShortMessageArgument receiver is nil", ber.ErrInvalidValue)
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
		if constraintErr := checkEncodedLength(nil, sd78d83_11, "37.4", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_smrpui, encodeErr_enc_smrpui := ber.EncodeOctetString([]byte(v.SmRPUI))
	if encodeErr_enc_smrpui != nil {
		return nil, qualifyBERError(encodeErr_enc_smrpui, "sm-RP-UI", "encoding", true)
	}
	children = append(children, enc_smrpui...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ForwardShortMessageArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ForwardShortMessageArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ForwardShortMessageArgument from BER/DER format.
func (destination *ForwardShortMessageArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ForwardShortMessageArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(ForwardShortMessageArgument)

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
			var probe ForwardShortMessageArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_11, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ForwardShortMessageArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ForwardShortMessageArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ForwardShortMessageArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardShortMessageArgument", Cause: ber.ErrExtraData}
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
		v.SmRPUI = SMRPUI(val_smrpui)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.SmRPUI) < 1 || len(v.SmRPUI) > 200 {
			if constraintErr := checkDecodedLength(opts, sd78d83_11, "37.4", "sm-RP-UI", "SIZE (1..200)", len(v.SmRPUI)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ForwardShortMessageArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ForwardSsNotificationArgument to BER format.
func (v *ForwardSsNotificationArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ForwardSsNotificationArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ForwardSsNotificationArgument).MarshalBER, (*ForwardSsNotificationArgument).marshalBER, 3)

}
func (v *ForwardSsNotificationArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, sd78d83_12, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_12, "37.4", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", false)
		}
		retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sscode)
		if tagErr_enc_sscode != nil {
			return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", false)
		}
		enc_sscode = retagged_enc_sscode
		children = append(children, enc_sscode...)
	}
	if v.Teleservice != nil {
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_12, "37.4", "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(*v.Teleservice))
		if encodeErr_enc_teleservice != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservice, "teleservice", "encoding", false)
		}
		retagged_enc_teleservice, tagErr_enc_teleservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_teleservice)
		if tagErr_enc_teleservice != nil {
			return nil, qualifyBERError(tagErr_enc_teleservice, "teleservice", "encoding", false)
		}
		enc_teleservice = retagged_enc_teleservice
		children = append(children, enc_teleservice...)
	}
	if v.BearerService != nil {
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_12, "37.4", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservice, encodeErr_enc_bearerservice := ber.EncodeOctetString([]byte(*v.BearerService))
		if encodeErr_enc_bearerservice != nil {
			return nil, qualifyBERError(encodeErr_enc_bearerservice, "bearerService", "encoding", false)
		}
		retagged_enc_bearerservice, tagErr_enc_bearerservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_bearerservice)
		if tagErr_enc_bearerservice != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservice, "bearerService", "encoding", false)
		}
		enc_bearerservice = retagged_enc_bearerservice
		children = append(children, enc_bearerservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_12, "37.4", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
	if v.SsNotification != nil {
		if len(*v.SsNotification) < 1 || len(*v.SsNotification) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_12, "37.4", "ss-Notification", "SIZE (1)", len(*v.SsNotification)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssnotification, encodeErr_enc_ssnotification := ber.EncodeOctetString([]byte(*v.SsNotification))
		if encodeErr_enc_ssnotification != nil {
			return nil, qualifyBERError(encodeErr_enc_ssnotification, "ss-Notification", "encoding", false)
		}
		retagged_enc_ssnotification, tagErr_enc_ssnotification := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ssnotification)
		if tagErr_enc_ssnotification != nil {
			return nil, qualifyBERError(tagErr_enc_ssnotification, "ss-Notification", "encoding", false)
		}
		enc_ssnotification = retagged_enc_ssnotification
		children = append(children, enc_ssnotification...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ForwardSsNotificationArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ForwardSsNotificationArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ForwardSsNotificationArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ForwardSsNotificationArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, sd78d83_12, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.SsCode != nil {
		if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_12, "37.4", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscode, encodeErr_enc_sscode := ber.EncodeOctetString([]byte(*v.SsCode))
		if encodeErr_enc_sscode != nil {
			return nil, qualifyBERError(encodeErr_enc_sscode, "ss-Code", "encoding", true)
		}
		retagged_enc_sscode, tagErr_enc_sscode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_sscode)
		if tagErr_enc_sscode != nil {
			return nil, qualifyBERError(tagErr_enc_sscode, "ss-Code", "encoding", true)
		}
		enc_sscode = retagged_enc_sscode
		children = append(children, enc_sscode...)
	}
	if v.Teleservice != nil {
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_12, "37.4", "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(*v.Teleservice))
		if encodeErr_enc_teleservice != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservice, "teleservice", "encoding", true)
		}
		retagged_enc_teleservice, tagErr_enc_teleservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_teleservice)
		if tagErr_enc_teleservice != nil {
			return nil, qualifyBERError(tagErr_enc_teleservice, "teleservice", "encoding", true)
		}
		enc_teleservice = retagged_enc_teleservice
		children = append(children, enc_teleservice...)
	}
	if v.BearerService != nil {
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_12, "37.4", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservice, encodeErr_enc_bearerservice := ber.EncodeOctetString([]byte(*v.BearerService))
		if encodeErr_enc_bearerservice != nil {
			return nil, qualifyBERError(encodeErr_enc_bearerservice, "bearerService", "encoding", true)
		}
		retagged_enc_bearerservice, tagErr_enc_bearerservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_bearerservice)
		if tagErr_enc_bearerservice != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservice, "bearerService", "encoding", true)
		}
		enc_bearerservice = retagged_enc_bearerservice
		children = append(children, enc_bearerservice...)
	}
	if v.SsStatus != nil {
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_12, "37.4", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
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
	if v.SsNotification != nil {
		if len(*v.SsNotification) < 1 || len(*v.SsNotification) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_12, "37.4", "ss-Notification", "SIZE (1)", len(*v.SsNotification)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_ssnotification, encodeErr_enc_ssnotification := ber.EncodeOctetString([]byte(*v.SsNotification))
		if encodeErr_enc_ssnotification != nil {
			return nil, qualifyBERError(encodeErr_enc_ssnotification, "ss-Notification", "encoding", true)
		}
		retagged_enc_ssnotification, tagErr_enc_ssnotification := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_ssnotification)
		if tagErr_enc_ssnotification != nil {
			return nil, qualifyBERError(tagErr_enc_ssnotification, "ss-Notification", "encoding", true)
		}
		enc_ssnotification = retagged_enc_ssnotification
		children = append(children, enc_ssnotification...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ForwardSsNotificationArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ForwardSsNotificationArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ForwardSsNotificationArgument from BER/DER format.
func (destination *ForwardSsNotificationArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ForwardSsNotificationArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(ForwardSsNotificationArgument)

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
			var probe ForwardSsNotificationArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_12, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ForwardSsNotificationArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ForwardSsNotificationArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ForwardSsNotificationArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ForwardSsNotificationArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
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
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, sd78d83_12, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ss-Code
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
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
				tmp_sscode := SSCode(decVal_sscode)
				v.SsCode = &tmp_sscode
				if offset < 0 || offset >
					len(content) || n_sscode < 0 || n_sscode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sscode
				if len(*v.SsCode) < 1 || len(*v.SsCode) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_12, "37.4", "ss-Code", "SIZE (1)", len(*v.SsCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode teleservice
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "teleservice", content[offset:])
				decodedTag_teleservice, n_teleservice, rawVal_teleservice, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "teleservice", "decoding", false)
				}
				if decodedTag_teleservice.Class != tag.ClassContextSpecific || decodedTag_teleservice.Number != 2 {
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
					if constraintErr := checkDecodedLength(opts, sd78d83_12, "37.4", "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode bearerService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "bearerService", content[offset:])
				decodedTag_bearerservice, n_bearerservice, rawVal_bearerservice, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bearerService", "decoding", false)
				}
				if decodedTag_bearerservice.Class != tag.ClassContextSpecific || decodedTag_bearerservice.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_bearerservice), "bearerService", "decoding", false)
				}
				decVal_bearerservice, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_bearerservice.Constructed, rawVal_bearerservice, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "bearerService", "decoding", false)
				}
				tmp_bearerservice := BearerServiceCode(decVal_bearerservice)
				v.BearerService = &tmp_bearerservice
				if offset < 0 || offset >
					len(content) || n_bearerservice < 0 || n_bearerservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bearerservice
				if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_12, "37.4", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
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
					len(content) || n_ssstatus < 0 || n_ssstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssstatus
				if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_12, "37.4", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ss-Notification
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "ss-Notification", content[offset:])
				decodedTag_ssnotification, n_ssnotification, rawVal_ssnotification, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-Notification", "decoding", false)
				}
				if decodedTag_ssnotification.Class != tag.ClassContextSpecific || decodedTag_ssnotification.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_ssnotification), "ss-Notification", "decoding", false)
				}
				decVal_ssnotification, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_ssnotification.Constructed, rawVal_ssnotification, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "ss-Notification", "decoding", false)
				}
				tmp_ssnotification := SSNotification(decVal_ssnotification)
				v.SsNotification = &tmp_ssnotification
				if offset < 0 || offset >
					len(content) || n_ssnotification < 0 || n_ssnotification > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_ssnotification
				if len(*v.SsNotification) < 1 || len(*v.SsNotification) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_12, "37.4", "ss-Notification", "SIZE (1)", len(*v.SsNotification)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ForwardSsNotificationArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes InsertSubscriberDataArgument to BER format.
func (v *InsertSubscriberDataArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: InsertSubscriberDataArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*InsertSubscriberDataArgument).MarshalBER, (*InsertSubscriberDataArgument).marshalBER, 3)

}
func (v *InsertSubscriberDataArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, sd78d83_13, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_13, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_13, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, sd78d83_13, "37.4", "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
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
			if constraintErr := checkEncodedValue(opts, sd78d83_13, "15", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, sd78d83_13, "37.4", "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, sd78d83_13, "37.4", "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(opts, sd78d83_13, "37.4", "provisonedSupplServices", "SIZE (1..30)", len((v.ProvisonedSupplServices).Values)); constraintErr != nil {
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
func (v *InsertSubscriberDataArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes InsertSubscriberDataArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *InsertSubscriberDataArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InsertSubscriberDataArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, sd78d83_13, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkEncodedLength(nil, sd78d83_13, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_13, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(nil, sd78d83_13, "37.4", "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
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
			if constraintErr := checkEncodedValue(nil, sd78d83_13, "15", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(nil, sd78d83_13, "37.4", "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(nil, sd78d83_13, "37.4", "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
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
			if constraintErr := checkEncodedLength(nil, sd78d83_13, "37.4", "provisonedSupplServices", "SIZE (1..30)", len((v.ProvisonedSupplServices).Values)); constraintErr != nil {
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
		return nil, fmt.Errorf("%s: %w", "encoding InsertSubscriberDataArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *InsertSubscriberDataArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes InsertSubscriberDataArgument from BER/DER format.
func (destination *InsertSubscriberDataArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: InsertSubscriberDataArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(InsertSubscriberDataArgument)

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
			var probe InsertSubscriberDataArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_13, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = InsertSubscriberDataArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*InsertSubscriberDataArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding InsertSubscriberDataArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InsertSubscriberDataArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
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
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, sd78d83_13, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
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
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
					if constraintErr := checkDecodedLength(opts, sd78d83_13, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_13, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
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
					if constraintErr := checkDecodedLength(opts, sd78d83_13, "37.4", "category", "SIZE (1)", len(*v.Category)); constraintErr != nil {
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
					len(content) || n_subscriberstatus < 0 || n_subscriberstatus > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_subscriberstatus
				if int64(*v.SubscriberStatus) != 0 && int64(*v.SubscriberStatus) != 1 {
					if constraintErr := checkDecodedValue(opts, sd78d83_13, "15", "subscriberStatus", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(*v.SubscriberStatus))); constraintErr != nil {
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
					len(content) || n_bearerservicelist < 0 || n_bearerservicelist > len(
					content[offset:]) {
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
					len(content) || n_bearerservicelist < 0 || n_bearerservicelist > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bearerservicelist
				if len((v.BearerServiceList).Values) < 1 || len((v.BearerServiceList).Values) > 50 {
					if constraintErr := checkDecodedLength(opts, sd78d83_13, "37.4", "bearerServiceList", "SIZE (1..50)", len((v.BearerServiceList).Values)); constraintErr != nil {
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
					len(content) || n_teleservicelist < 0 || n_teleservicelist > len(content[offset:]) {
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
					len(content) || n_teleservicelist < 0 || n_teleservicelist > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_teleservicelist
				if len((v.TeleserviceList).Values) < 1 || len((v.TeleserviceList).Values) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_13, "37.4", "teleserviceList", "SIZE (1..20)", len((v.TeleserviceList).Values)); constraintErr != nil {
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
					if constraintErr := checkDecodedLength(opts, sd78d83_13, "37.4", "provisonedSupplServices", "SIZE (1..30)", len((v.ProvisonedSupplServices).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "InsertSubscriberDataArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes InterrogateSSArgument to BER format.
func (v *InterrogateSSArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: InterrogateSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*InterrogateSSArgument).MarshalBER, (*InterrogateSSArgument).marshalBER, 3)

}
func (v *InterrogateSSArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, sd78d83_14, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *InterrogateSSArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes InterrogateSSArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *InterrogateSSArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InterrogateSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, sd78d83_14, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding InterrogateSSArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *InterrogateSSArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes InterrogateSSArgument from BER/DER format.
func (destination *InterrogateSSArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: InterrogateSSArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(InterrogateSSArgument)

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
			var probe InterrogateSSArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_14, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = InterrogateSSArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*InterrogateSSArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding InterrogateSSArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InterrogateSSArgument", Cause: ber.ErrExtraData}
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
			if constraintErr := checkDecodedLength(opts, sd78d83_14, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "InterrogateSSArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes InterrogateSSResult to BER format.
func (v *InterrogateSSResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: InterrogateSSResult receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*InterrogateSSResult).MarshalBER, (*InterrogateSSResult).marshalBER, 3)

}
func (v *InterrogateSSResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *InterrogateSSResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case InterrogateSSResultChoiceSsStatus:
		if v.SsStatus == nil {
			return nil, fmt.Errorf("%w: choice InterrogateSSResult: ss-Status is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.SsStatus))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "ss-Status", "encoding", false)
		}
		if len(*v.SsStatus) < 1 || len(*v.SsStatus) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_15, "37.4", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "ss-Status", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case InterrogateSSResultChoiceForwardedToNumber:
		if v.ForwardedToNumber == nil {
			return nil, fmt.Errorf("%w: choice InterrogateSSResult: forwardedToNumber is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.ForwardedToNumber))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "forwardedToNumber", "encoding", false)
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_15, "37.4", "forwardedToNumber", "SIZE (1..10)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_15, "37.4", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "forwardedToNumber", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	case InterrogateSSResultChoiceActivesBasicServices:
		enc_2, err := MarshalBERBasicServiceList(v.ActivesBasicServices, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "activesBasicServices"))...)
		if err != nil {
			return nil, qualifyBERError(err, "activesBasicServices", "encoding", false)
		}
		if len((v.ActivesBasicServices).Values) < 1 || len((v.ActivesBasicServices).Values) > 70 {
			if constraintErr := checkEncodedLength(opts, sd78d83_15, "37.4", "activesBasicServices", "SIZE (1..70)", len((v.ActivesBasicServices).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_2, tagErr_enc_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_2)
		if tagErr_enc_2 != nil {
			return nil, qualifyBERError(tagErr_enc_2, "activesBasicServices", "encoding", false)
		}
		enc_2 = retagged_enc_2
		return enc_2, nil
	case InterrogateSSResultChoiceForwardingFeatureList:
		enc_3, err := MarshalBERForwardingFeatureList(v.ForwardingFeatureList, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "forwardingFeatureList"))...)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", false)
		}
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := checkEncodedLength(opts, sd78d83_15, "37.4", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_3, tagErr_enc_3 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_3)
		if tagErr_enc_3 != nil {
			return nil, qualifyBERError(tagErr_enc_3, "forwardingFeatureList", "encoding", false)
		}
		enc_3 = retagged_enc_3
		return enc_3, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for InterrogateSSResult", v.Choice)
	}
}

// MarshalDER encodes InterrogateSSResult to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *InterrogateSSResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InterrogateSSResult receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case InterrogateSSResultChoiceActivesBasicServices:
		enc_der_2, err := MarshalDERBasicServiceList(v.ActivesBasicServices)
		if err != nil {
			return nil, qualifyBERError(err, "activesBasicServices", "encoding", true)
		}
		if len((v.ActivesBasicServices).Values) < 1 || len((v.ActivesBasicServices).Values) > 70 {
			if constraintErr := checkEncodedLength(nil, sd78d83_15, "37.4", "activesBasicServices", "SIZE (1..70)", len((v.ActivesBasicServices).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_der_2, tagErr_enc_der_2 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_der_2)
		if tagErr_enc_der_2 != nil {
			return nil, qualifyBERError(tagErr_enc_der_2, "activesBasicServices", "encoding", true)
		}
		enc_der_2 = retagged_enc_der_2
		if derErr := ber.ValidateDEREncodedElement(enc_der_2); derErr != nil {
			return nil, qualifyBERError(derErr, "activesBasicServices", "encoding", true)
		}
		return enc_der_2, nil
	case InterrogateSSResultChoiceForwardingFeatureList:
		enc_der_3, err := MarshalDERForwardingFeatureList(v.ForwardingFeatureList)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", true)
		}
		if len((v.ForwardingFeatureList).Values) < 1 || len((v.ForwardingFeatureList).Values) > 13 {
			if constraintErr := checkEncodedLength(nil, sd78d83_15, "37.4", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
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
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case InterrogateSSResultChoiceSsStatus:
			return nil, qualifyBERError(err, "ss-Status", "encoding", true)
		case InterrogateSSResultChoiceForwardedToNumber:
			return nil, qualifyBERError(err, "forwardedToNumber", "encoding", true)
		case InterrogateSSResultChoiceActivesBasicServices:
			return nil, qualifyBERError(err, "activesBasicServices", "encoding", true)
		case InterrogateSSResultChoiceForwardingFeatureList:
			return nil, qualifyBERError(err, "forwardingFeatureList", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding InterrogateSSResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *InterrogateSSResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes InterrogateSSResult from BER/DER format.
func (destination *InterrogateSSResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: InterrogateSSResult destination is nil", ber.ErrInvalidValue)
	}
	v := new(InterrogateSSResult)

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
				opts, v, &v.berReplayNode_, (*InterrogateSSResult).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe InterrogateSSResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_15, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = InterrogateSSResult{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for InterrogateSSResult CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for InterrogateSSResult: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding InterrogateSSResult CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "InterrogateSSResult", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "InterrogateSSResult.activesBasicServices", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "InterrogateSSResult.forwardingFeatureList", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = InterrogateSSResultChoiceSsStatus
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
			if constraintErr := checkDecodedLength(opts, sd78d83_15, "37.4", "ss-Status", "SIZE (1)", len(*v.SsStatus)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = InterrogateSSResultChoiceForwardedToNumber
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
		tmp := IsdnAddressString(decVal)
		v.ForwardedToNumber = &tmp
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_15, "37.4", "forwardedToNumber", "SIZE (1..10)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_15, "37.4", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 && peekTag.Constructed == true {
		v.Choice = InterrogateSSResultChoiceActivesBasicServices
		ber.MarkPreflightTarget(opts, "activesBasicServices", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "activesBasicServices", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		dec, unmErr := UnmarshalBERBasicServiceList(reconstructed, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "activesBasicServices"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "activesBasicServices", "decoding", false)
		}
		v.ActivesBasicServices = dec
		if len((v.ActivesBasicServices).Values) < 1 || len((v.ActivesBasicServices).Values) > 70 {
			if constraintErr := checkDecodedLength(opts, sd78d83_15, "37.4", "activesBasicServices", "SIZE (1..70)", len((v.ActivesBasicServices).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 && peekTag.Constructed == true {
		v.Choice = InterrogateSSResultChoiceForwardingFeatureList
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
			if constraintErr := checkDecodedLength(opts, sd78d83_15, "37.4", "forwardingFeatureList", "SIZE (1..13)", len((v.ForwardingFeatureList).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for InterrogateSSResult CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes InvokeSSArgument to BER format.
func (v *InvokeSSArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: InvokeSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*InvokeSSArgument).MarshalBER, (*InvokeSSArgument).marshalBER, 3)

}
func (v *InvokeSSArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, sd78d83_16, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	if v.UserToUserServiceIndicator != nil {
		if len(*v.UserToUserServiceIndicator) < 1 || len(*v.UserToUserServiceIndicator) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_16, "37.4", "userToUserServiceIndicator", "SIZE (1)", len(*v.UserToUserServiceIndicator)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_usertouserserviceindicator, encodeErr_enc_usertouserserviceindicator := ber.EncodeOctetString([]byte(*v.UserToUserServiceIndicator))
		if encodeErr_enc_usertouserserviceindicator != nil {
			return nil, qualifyBERError(encodeErr_enc_usertouserserviceindicator, "userToUserServiceIndicator", "encoding", false)
		}
		retagged_enc_usertouserserviceindicator, tagErr_enc_usertouserserviceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_usertouserserviceindicator)
		if tagErr_enc_usertouserserviceindicator != nil {
			return nil, qualifyBERError(tagErr_enc_usertouserserviceindicator, "userToUserServiceIndicator", "encoding", false)
		}
		enc_usertouserserviceindicator = retagged_enc_usertouserserviceindicator
		children = append(children, enc_usertouserserviceindicator...)
	}
	if v.CugIndex != nil {
		if len(*v.CugIndex) < 1 || len(*v.CugIndex) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_16, "37.4", "cug-Index", "SIZE (1)", len(*v.CugIndex)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cugindex, encodeErr_enc_cugindex := ber.EncodeOctetString([]byte(*v.CugIndex))
		if encodeErr_enc_cugindex != nil {
			return nil, qualifyBERError(encodeErr_enc_cugindex, "cug-Index", "encoding", false)
		}
		retagged_enc_cugindex, tagErr_enc_cugindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_cugindex)
		if tagErr_enc_cugindex != nil {
			return nil, qualifyBERError(tagErr_enc_cugindex, "cug-Index", "encoding", false)
		}
		enc_cugindex = retagged_enc_cugindex
		children = append(children, enc_cugindex...)
	}
	if v.NumberOfConferees != nil {
		if !(int64(*v.NumberOfConferees) >= 1 && int64(*v.NumberOfConferees) <= 10) {
			if constraintErr := checkEncodedValue(opts, sd78d83_16, "37.3", "numberOfConferees", "(1..10)", ber.ObserveInteger(int64(*v.NumberOfConferees))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numberofconferees := ber.EncodeInteger(int64(*v.NumberOfConferees))
		retagged_enc_numberofconferees, tagErr_enc_numberofconferees := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_numberofconferees)
		if tagErr_enc_numberofconferees != nil {
			return nil, qualifyBERError(tagErr_enc_numberofconferees, "numberOfConferees", "encoding", false)
		}
		enc_numberofconferees = retagged_enc_numberofconferees
		children = append(children, enc_numberofconferees...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *InvokeSSArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes InvokeSSArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *InvokeSSArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: InvokeSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, sd78d83_16, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	if v.UserToUserServiceIndicator != nil {
		if len(*v.UserToUserServiceIndicator) < 1 || len(*v.UserToUserServiceIndicator) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_16, "37.4", "userToUserServiceIndicator", "SIZE (1)", len(*v.UserToUserServiceIndicator)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_usertouserserviceindicator, encodeErr_enc_usertouserserviceindicator := ber.EncodeOctetString([]byte(*v.UserToUserServiceIndicator))
		if encodeErr_enc_usertouserserviceindicator != nil {
			return nil, qualifyBERError(encodeErr_enc_usertouserserviceindicator, "userToUserServiceIndicator", "encoding", true)
		}
		retagged_enc_usertouserserviceindicator, tagErr_enc_usertouserserviceindicator := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_usertouserserviceindicator)
		if tagErr_enc_usertouserserviceindicator != nil {
			return nil, qualifyBERError(tagErr_enc_usertouserserviceindicator, "userToUserServiceIndicator", "encoding", true)
		}
		enc_usertouserserviceindicator = retagged_enc_usertouserserviceindicator
		children = append(children, enc_usertouserserviceindicator...)
	}
	if v.CugIndex != nil {
		if len(*v.CugIndex) < 1 || len(*v.CugIndex) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_16, "37.4", "cug-Index", "SIZE (1)", len(*v.CugIndex)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cugindex, encodeErr_enc_cugindex := ber.EncodeOctetString([]byte(*v.CugIndex))
		if encodeErr_enc_cugindex != nil {
			return nil, qualifyBERError(encodeErr_enc_cugindex, "cug-Index", "encoding", true)
		}
		retagged_enc_cugindex, tagErr_enc_cugindex := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_cugindex)
		if tagErr_enc_cugindex != nil {
			return nil, qualifyBERError(tagErr_enc_cugindex, "cug-Index", "encoding", true)
		}
		enc_cugindex = retagged_enc_cugindex
		children = append(children, enc_cugindex...)
	}
	if v.NumberOfConferees != nil {
		if !(int64(*v.NumberOfConferees) >= 1 && int64(*v.NumberOfConferees) <= 10) {
			if constraintErr := checkEncodedValue(nil, sd78d83_16, "37.3", "numberOfConferees", "(1..10)", ber.ObserveInteger(int64(*v.NumberOfConferees))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numberofconferees := ber.EncodeInteger(int64(*v.NumberOfConferees))
		retagged_enc_numberofconferees, tagErr_enc_numberofconferees := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_numberofconferees)
		if tagErr_enc_numberofconferees != nil {
			return nil, qualifyBERError(tagErr_enc_numberofconferees, "numberOfConferees", "encoding", true)
		}
		enc_numberofconferees = retagged_enc_numberofconferees
		children = append(children, enc_numberofconferees...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding InvokeSSArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *InvokeSSArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes InvokeSSArgument from BER/DER format.
func (destination *InvokeSSArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: InvokeSSArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(InvokeSSArgument)

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
			var probe InvokeSSArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_16, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = InvokeSSArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*InvokeSSArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding InvokeSSArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "InvokeSSArgument", Cause: ber.ErrExtraData}
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
			if constraintErr := checkDecodedLength(opts, sd78d83_16, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
	// Decode userToUserServiceIndicator
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "userToUserServiceIndicator", content[offset:])
				decodedTag_usertouserserviceindicator, n_usertouserserviceindicator, rawVal_usertouserserviceindicator, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "userToUserServiceIndicator", "decoding", false)
				}
				if decodedTag_usertouserserviceindicator.Class != tag.ClassContextSpecific || decodedTag_usertouserserviceindicator.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_usertouserserviceindicator), "userToUserServiceIndicator", "decoding", false)
				}
				decVal_usertouserserviceindicator, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_usertouserserviceindicator.Constructed, rawVal_usertouserserviceindicator, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "userToUserServiceIndicator", "decoding", false)
				}
				tmp_usertouserserviceindicator := UserToUserServiceIndicator(decVal_usertouserserviceindicator)
				v.UserToUserServiceIndicator = &tmp_usertouserserviceindicator
				if offset < 0 || offset >
					len(content) || n_usertouserserviceindicator < 0 || n_usertouserserviceindicator >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_usertouserserviceindicator
				if len(*v.UserToUserServiceIndicator) < 1 || len(*v.UserToUserServiceIndicator) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_16, "37.4", "userToUserServiceIndicator", "SIZE (1)", len(*v.UserToUserServiceIndicator)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cug-Index
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "cug-Index", content[offset:])
				decodedTag_cugindex, n_cugindex, rawVal_cugindex, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cug-Index", "decoding", false)
				}
				if decodedTag_cugindex.Class != tag.ClassContextSpecific || decodedTag_cugindex.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_cugindex), "cug-Index", "decoding", false)
				}
				decVal_cugindex, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cugindex.Constructed, rawVal_cugindex, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "cug-Index", "decoding", false)
				}
				tmp_cugindex := CUGIndex(decVal_cugindex)
				v.CugIndex = &tmp_cugindex
				if offset < 0 || offset >
					len(content) || n_cugindex < 0 || n_cugindex > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cugindex
				if len(*v.CugIndex) < 1 || len(*v.CugIndex) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_16, "37.4", "cug-Index", "SIZE (1)", len(*v.CugIndex)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode numberOfConferees
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "numberOfConferees", content[offset:])
				decodedTag_numberofconferees, n_numberofconferees, rawVal_numberofconferees, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "numberOfConferees", "decoding", false)
				}
				if decodedTag_numberofconferees.Class != tag.ClassContextSpecific || decodedTag_numberofconferees.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_numberofconferees), "numberOfConferees", "decoding", false)
				}
				if decodedTag_numberofconferees.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_numberofconferees), "numberOfConferees", "decoding", false)
				}
				decVal_numberofconferees, intErr := ber.DecodeIntegerValue(rawVal_numberofconferees)
				if intErr != nil {
					return qualifyBERError(intErr, "numberOfConferees", "decoding", false)
				}
				tmp_numberofconferees := NumberOfConferees(decVal_numberofconferees)
				v.NumberOfConferees = &tmp_numberofconferees
				if offset < 0 || offset >
					len(content) || n_numberofconferees < 0 || n_numberofconferees >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_numberofconferees
				if !(int64(*v.NumberOfConferees) >= 1 && int64(*v.NumberOfConferees) <= 10) {
					if constraintErr := checkDecodedValue(opts, sd78d83_16, "37.3", "numberOfConferees", "(1..10)", ber.ObserveInteger(int64(*v.NumberOfConferees))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "InvokeSSArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes NoteInternalHandoverArgument to BER format.
func (v *NoteInternalHandoverArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: NoteInternalHandoverArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*NoteInternalHandoverArgument).MarshalBER, (*NoteInternalHandoverArgument).marshalBER, 3)

}
func (v *NoteInternalHandoverArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.HandoverType) != 0 && int64(v.HandoverType) != 1 {
		if constraintErr := checkEncodedValue(opts, sd78d83_17, "15", "handoverType", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.HandoverType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_handovertype := ber.EncodeEnumerated(int64(v.HandoverType))
	children = append(children, enc_handovertype...)
	if v.TargetCellId != nil {
		if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
			if constraintErr := checkEncodedLength(opts, sd78d83_17, "37.4", "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(*v.TargetCellId))
		if encodeErr_enc_targetcellid != nil {
			return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", false)
		}
		retagged_enc_targetcellid, tagErr_enc_targetcellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_targetcellid)
		if tagErr_enc_targetcellid != nil {
			return nil, qualifyBERError(tagErr_enc_targetcellid, "targetCellId", "encoding", false)
		}
		enc_targetcellid = retagged_enc_targetcellid
		children = append(children, enc_targetcellid...)
	}
	if v.ChannelId != nil {
		enc_channelid, err := v.ChannelId.MarshalBER(ber.ChildEncodeOptions(opts, "channelId")...)
		if err != nil {
			return nil, qualifyBERError(err, "channelId", "encoding", false)
		}
		retagged_enc_channelid, tagErr_enc_channelid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_channelid)
		if tagErr_enc_channelid != nil {
			return nil, qualifyBERError(tagErr_enc_channelid, "channelId", "encoding", false)
		}
		enc_channelid = retagged_enc_channelid
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_channelid)
		children = append(children, enc_channelid...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *NoteInternalHandoverArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes NoteInternalHandoverArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *NoteInternalHandoverArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: NoteInternalHandoverArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.HandoverType) != 0 && int64(v.HandoverType) != 1 {
		if constraintErr := checkEncodedValue(nil, sd78d83_17, "15", "handoverType", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.HandoverType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_handovertype := ber.EncodeEnumerated(int64(v.HandoverType))
	children = append(children, enc_handovertype...)
	if v.TargetCellId != nil {
		if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
			if constraintErr := checkEncodedLength(nil, sd78d83_17, "37.4", "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(*v.TargetCellId))
		if encodeErr_enc_targetcellid != nil {
			return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", true)
		}
		retagged_enc_targetcellid, tagErr_enc_targetcellid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_targetcellid)
		if tagErr_enc_targetcellid != nil {
			return nil, qualifyBERError(tagErr_enc_targetcellid, "targetCellId", "encoding", true)
		}
		enc_targetcellid = retagged_enc_targetcellid
		children = append(children, enc_targetcellid...)
	}
	if v.ChannelId != nil {
		enc_channelid, err := v.ChannelId.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "channelId", "encoding", true)
		}
		retagged_enc_channelid, tagErr_enc_channelid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_channelid)
		if tagErr_enc_channelid != nil {
			return nil, qualifyBERError(tagErr_enc_channelid, "channelId", "encoding", true)
		}
		enc_channelid = retagged_enc_channelid
		children = append(children, enc_channelid...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding NoteInternalHandoverArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *NoteInternalHandoverArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes NoteInternalHandoverArgument from BER/DER format.
func (destination *NoteInternalHandoverArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: NoteInternalHandoverArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(NoteInternalHandoverArgument)

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
			var probe NoteInternalHandoverArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_17, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = NoteInternalHandoverArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*NoteInternalHandoverArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding NoteInternalHandoverArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "NoteInternalHandoverArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode handoverType
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field handoverType", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "handoverType", content[offset:])
		val_handovertype, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "handoverType", "decoding", false)
		}
		v.HandoverType = HandoverType(val_handovertype)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.HandoverType) != 0 && int64(v.HandoverType) != 1 {
			if constraintErr := checkDecodedValue(opts, sd78d83_17, "15", "handoverType", "ENUMERATED {0, 1}", ber.ObserveInteger(int64(v.HandoverType))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode targetCellId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "targetCellId", content[offset:])
				decodedTag_targetcellid, n_targetcellid, rawVal_targetcellid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "targetCellId", "decoding", false)
				}
				if decodedTag_targetcellid.Class != tag.ClassContextSpecific || decodedTag_targetcellid.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_targetcellid), "targetCellId", "decoding", false)
				}
				decVal_targetcellid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_targetcellid.Constructed, rawVal_targetcellid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "targetCellId", "decoding", false)
				}
				tmp_targetcellid := GlobalCellId(decVal_targetcellid)
				v.TargetCellId = &tmp_targetcellid
				if offset < 0 || offset >
					len(content) || n_targetcellid < 0 || n_targetcellid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_targetcellid
				if len(*v.TargetCellId) < 5 || len(*v.TargetCellId) > 7 {
					if constraintErr := checkDecodedLength(opts, sd78d83_17, "37.4", "targetCellId", "SIZE (5..7)", len(*v.TargetCellId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode channelId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "channelId", content[offset:])
				decodedTag_channelid, n_channelid, rawVal_channelid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "channelId", "decoding", false)
				}
				if decodedTag_channelid.Class != tag.ClassContextSpecific || decodedTag_channelid.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_channelid), "channelId", "decoding", false)
				}
				if decodedTag_channelid.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_channelid), "channelId", "decoding", false)
				}
				_ = rawVal_channelid
				if offset < 0 || offset >
					len(content) || n_channelid < 0 || n_channelid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_channelid, reconstructionErr_channelid := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_channelid])
				if reconstructionErr_channelid != nil {
					return qualifyBERError(reconstructionErr_channelid, "channelId", "decoding", false)
				}
				var dec_channelid ExternalSignalInfo
				if unmErr := dec_channelid.UnmarshalBER(reconstructed_channelid, ber.ChildDecodeOptions(opts, "channelId")...); unmErr != nil {
					return qualifyBERError(unmErr, "channelId", "decoding", false)
				}
				v.ChannelId = &dec_channelid
				if offset < 0 || offset >
					len(content) || n_channelid < 0 || n_channelid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_channelid
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "NoteInternalHandoverArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes PageArgument to BER format.
func (v *PageArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PageArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PageArgument).MarshalBER, (*PageArgument).marshalBER, 3)

}
func (v *PageArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, sd78d83_18, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
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
	if v.Tmsi != nil {
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := checkEncodedLength(opts, sd78d83_18, "37.4", "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tmsi, encodeErr_enc_tmsi := ber.EncodeOctetString([]byte(*v.Tmsi))
		if encodeErr_enc_tmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_tmsi, "tmsi", "encoding", false)
		}
		retagged_enc_tmsi, tagErr_enc_tmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tmsi)
		if tagErr_enc_tmsi != nil {
			return nil, qualifyBERError(tagErr_enc_tmsi, "tmsi", "encoding", false)
		}
		enc_tmsi = retagged_enc_tmsi
		children = append(children, enc_tmsi...)
	}
	if len(v.LocAreaId) < 2 || len(v.LocAreaId) > 5 {
		if constraintErr := checkEncodedLength(opts, sd78d83_18, "37.4", "locAreaId", "SIZE (2..5)", len(v.LocAreaId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_locareaid, encodeErr_enc_locareaid := ber.EncodeOctetString([]byte(v.LocAreaId))
	if encodeErr_enc_locareaid != nil {
		return nil, qualifyBERError(encodeErr_enc_locareaid, "locAreaId", "encoding", false)
	}
	retagged_enc_locareaid, tagErr_enc_locareaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_locareaid)
	if tagErr_enc_locareaid != nil {
		return nil, qualifyBERError(tagErr_enc_locareaid, "locAreaId", "encoding", false)
	}
	enc_locareaid = retagged_enc_locareaid
	children = append(children, enc_locareaid...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PageArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PageArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PageArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PageArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, sd78d83_18, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
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
	if v.Tmsi != nil {
		if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
			if constraintErr := checkEncodedLength(nil, sd78d83_18, "37.4", "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_tmsi, encodeErr_enc_tmsi := ber.EncodeOctetString([]byte(*v.Tmsi))
		if encodeErr_enc_tmsi != nil {
			return nil, qualifyBERError(encodeErr_enc_tmsi, "tmsi", "encoding", true)
		}
		retagged_enc_tmsi, tagErr_enc_tmsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tmsi)
		if tagErr_enc_tmsi != nil {
			return nil, qualifyBERError(tagErr_enc_tmsi, "tmsi", "encoding", true)
		}
		enc_tmsi = retagged_enc_tmsi
		children = append(children, enc_tmsi...)
	}
	if len(v.LocAreaId) < 2 || len(v.LocAreaId) > 5 {
		if constraintErr := checkEncodedLength(nil, sd78d83_18, "37.4", "locAreaId", "SIZE (2..5)", len(v.LocAreaId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_locareaid, encodeErr_enc_locareaid := ber.EncodeOctetString([]byte(v.LocAreaId))
	if encodeErr_enc_locareaid != nil {
		return nil, qualifyBERError(encodeErr_enc_locareaid, "locAreaId", "encoding", true)
	}
	retagged_enc_locareaid, tagErr_enc_locareaid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_locareaid)
	if tagErr_enc_locareaid != nil {
		return nil, qualifyBERError(tagErr_enc_locareaid, "locAreaId", "encoding", true)
	}
	enc_locareaid = retagged_enc_locareaid
	children = append(children, enc_locareaid...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PageArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PageArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PageArgument from BER/DER format.
func (destination *PageArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PageArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(PageArgument)

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
			var probe PageArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_18, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PageArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PageArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PageArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PageArgument", Cause: ber.ErrExtraData}
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
		if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, sd78d83_18, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode tmsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "tmsi", content[offset:])
				decodedTag_tmsi, n_tmsi, rawVal_tmsi, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "tmsi", "decoding", false)
				}
				if decodedTag_tmsi.Class != tag.ClassContextSpecific || decodedTag_tmsi.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tmsi), "tmsi", "decoding", false)
				}
				decVal_tmsi, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tmsi.Constructed, rawVal_tmsi, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "tmsi", "decoding", false)
				}
				tmp_tmsi := TMSI(decVal_tmsi)
				v.Tmsi = &tmp_tmsi
				if offset < 0 || offset >
					len(content) || n_tmsi < 0 || n_tmsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_tmsi
				if len(*v.Tmsi) < 1 || len(*v.Tmsi) > 4 {
					if constraintErr := checkDecodedLength(opts, sd78d83_18, "37.4", "tmsi", "SIZE (1..4)", len(*v.Tmsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode locAreaId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field locAreaId", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("%w: expected tag [%s %d] for locAreaId, got %s", ber.ErrUnexpectedElement, "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "locAreaId", content[offset:])
		decodedTag_locareaid, n_locareaid, rawVal_locareaid, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "locAreaId", "decoding", false)
		}
		if decodedTag_locareaid.Class != tag.ClassContextSpecific || decodedTag_locareaid.Number != 2 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_locareaid), "locAreaId", "decoding", false)
		}
		decVal_locareaid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_locareaid.Constructed, rawVal_locareaid, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "locAreaId", "decoding", false)
		}
		v.LocAreaId = LocAreaId(decVal_locareaid)
		if offset < 0 || offset >
			len(content) || n_locareaid < 0 || n_locareaid > len(
			content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_locareaid
		if len(v.LocAreaId) < 2 || len(v.LocAreaId) > 5 {
			if constraintErr := checkDecodedLength(opts, sd78d83_18, "37.4", "locAreaId", "SIZE (2..5)", len(v.LocAreaId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PageArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes PerformHandoverArgument to BER format.
func (v *PerformHandoverArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PerformHandoverArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PerformHandoverArgument).MarshalBER, (*PerformHandoverArgument).marshalBER, 3)

}
func (v *PerformHandoverArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
		if constraintErr := checkEncodedLength(opts, sd78d83_19, "37.4", "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(v.TargetCellId))
	if encodeErr_enc_targetcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", false)
	}
	children = append(children, enc_targetcellid...)
	if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
		if constraintErr := checkEncodedLength(opts, sd78d83_19, "37.4", "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servingcellid, encodeErr_enc_servingcellid := ber.EncodeOctetString([]byte(v.ServingCellId))
	if encodeErr_enc_servingcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_servingcellid, "servingCellId", "encoding", false)
	}
	children = append(children, enc_servingcellid...)
	if len(v.ChannelType) < 1 || len(v.ChannelType) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_19, "37.4", "channelType", "SIZE (1..10)", len(v.ChannelType)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_channeltype, encodeErr_enc_channeltype := ber.EncodeOctetString([]byte(v.ChannelType))
	if encodeErr_enc_channeltype != nil {
		return nil, qualifyBERError(encodeErr_enc_channeltype, "channelType", "encoding", false)
	}
	children = append(children, enc_channeltype...)
	if len(v.ClassmarkInformation) < 1 || len(v.ClassmarkInformation) > 2 {
		if constraintErr := checkEncodedLength(opts, sd78d83_19, "37.4", "classmarkInformation", "SIZE (1..2)", len(v.ClassmarkInformation)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_classmarkinformation, encodeErr_enc_classmarkinformation := ber.EncodeOctetString([]byte(v.ClassmarkInformation))
	if encodeErr_enc_classmarkinformation != nil {
		return nil, qualifyBERError(encodeErr_enc_classmarkinformation, "classmarkInformation", "encoding", false)
	}
	children = append(children, enc_classmarkinformation...)
	if v.HandoverPriority != nil {
		if len(*v.HandoverPriority) < 1 || len(*v.HandoverPriority) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_19, "37.4", "handoverPriority", "SIZE (1)", len(*v.HandoverPriority)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_handoverpriority, encodeErr_enc_handoverpriority := ber.EncodeOctetString([]byte(*v.HandoverPriority))
		if encodeErr_enc_handoverpriority != nil {
			return nil, qualifyBERError(encodeErr_enc_handoverpriority, "handoverPriority", "encoding", false)
		}
		retagged_enc_handoverpriority, tagErr_enc_handoverpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_handoverpriority)
		if tagErr_enc_handoverpriority != nil {
			return nil, qualifyBERError(tagErr_enc_handoverpriority, "handoverPriority", "encoding", false)
		}
		enc_handoverpriority = retagged_enc_handoverpriority
		children = append(children, enc_handoverpriority...)
	}
	if v.Kc != nil {
		if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
			if constraintErr := checkEncodedLength(opts, sd78d83_19, "37.4", "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(*v.Kc))
		if encodeErr_enc_kc != nil {
			return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", false)
		}
		retagged_enc_kc, tagErr_enc_kc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_kc)
		if tagErr_enc_kc != nil {
			return nil, qualifyBERError(tagErr_enc_kc, "kc", "encoding", false)
		}
		enc_kc = retagged_enc_kc
		children = append(children, enc_kc...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PerformHandoverArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PerformHandoverArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PerformHandoverArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PerformHandoverArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
		if constraintErr := checkEncodedLength(nil, sd78d83_19, "37.4", "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(v.TargetCellId))
	if encodeErr_enc_targetcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", true)
	}
	children = append(children, enc_targetcellid...)
	if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
		if constraintErr := checkEncodedLength(nil, sd78d83_19, "37.4", "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servingcellid, encodeErr_enc_servingcellid := ber.EncodeOctetString([]byte(v.ServingCellId))
	if encodeErr_enc_servingcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_servingcellid, "servingCellId", "encoding", true)
	}
	children = append(children, enc_servingcellid...)
	if len(v.ChannelType) < 1 || len(v.ChannelType) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_19, "37.4", "channelType", "SIZE (1..10)", len(v.ChannelType)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_channeltype, encodeErr_enc_channeltype := ber.EncodeOctetString([]byte(v.ChannelType))
	if encodeErr_enc_channeltype != nil {
		return nil, qualifyBERError(encodeErr_enc_channeltype, "channelType", "encoding", true)
	}
	children = append(children, enc_channeltype...)
	if len(v.ClassmarkInformation) < 1 || len(v.ClassmarkInformation) > 2 {
		if constraintErr := checkEncodedLength(nil, sd78d83_19, "37.4", "classmarkInformation", "SIZE (1..2)", len(v.ClassmarkInformation)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_classmarkinformation, encodeErr_enc_classmarkinformation := ber.EncodeOctetString([]byte(v.ClassmarkInformation))
	if encodeErr_enc_classmarkinformation != nil {
		return nil, qualifyBERError(encodeErr_enc_classmarkinformation, "classmarkInformation", "encoding", true)
	}
	children = append(children, enc_classmarkinformation...)
	if v.HandoverPriority != nil {
		if len(*v.HandoverPriority) < 1 || len(*v.HandoverPriority) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_19, "37.4", "handoverPriority", "SIZE (1)", len(*v.HandoverPriority)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_handoverpriority, encodeErr_enc_handoverpriority := ber.EncodeOctetString([]byte(*v.HandoverPriority))
		if encodeErr_enc_handoverpriority != nil {
			return nil, qualifyBERError(encodeErr_enc_handoverpriority, "handoverPriority", "encoding", true)
		}
		retagged_enc_handoverpriority, tagErr_enc_handoverpriority := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_handoverpriority)
		if tagErr_enc_handoverpriority != nil {
			return nil, qualifyBERError(tagErr_enc_handoverpriority, "handoverPriority", "encoding", true)
		}
		enc_handoverpriority = retagged_enc_handoverpriority
		children = append(children, enc_handoverpriority...)
	}
	if v.Kc != nil {
		if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
			if constraintErr := checkEncodedLength(nil, sd78d83_19, "37.4", "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(*v.Kc))
		if encodeErr_enc_kc != nil {
			return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", true)
		}
		retagged_enc_kc, tagErr_enc_kc := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_kc)
		if tagErr_enc_kc != nil {
			return nil, qualifyBERError(tagErr_enc_kc, "kc", "encoding", true)
		}
		enc_kc = retagged_enc_kc
		children = append(children, enc_kc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PerformHandoverArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PerformHandoverArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PerformHandoverArgument from BER/DER format.
func (destination *PerformHandoverArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PerformHandoverArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(PerformHandoverArgument)

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
			var probe PerformHandoverArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_19, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PerformHandoverArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PerformHandoverArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PerformHandoverArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PerformHandoverArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode targetCellId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field targetCellId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "targetCellId", content[offset:])
		val_targetcellid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "targetCellId", "decoding", false)
		}
		v.TargetCellId = GlobalCellId(val_targetcellid)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
			if constraintErr := checkDecodedLength(opts, sd78d83_19, "37.4", "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode servingCellId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field servingCellId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "servingCellId", content[offset:])
		val_servingcellid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "servingCellId", "decoding", false)
		}
		v.ServingCellId = GlobalCellId(val_servingcellid)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
			if constraintErr := checkDecodedLength(opts, sd78d83_19, "37.4", "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode channelType
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field channelType", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "channelType", content[offset:])
		val_channeltype, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "channelType", "decoding", false)
		}
		v.ChannelType = ChannelType(val_channeltype)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ChannelType) < 1 || len(v.ChannelType) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_19, "37.4", "channelType", "SIZE (1..10)", len(v.ChannelType)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode classmarkInformation
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field classmarkInformation", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "classmarkInformation", content[offset:])
		val_classmarkinformation, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "classmarkInformation", "decoding", false)
		}
		v.ClassmarkInformation = ClassmarkInformation(val_classmarkinformation)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ClassmarkInformation) < 1 || len(v.ClassmarkInformation) > 2 {
			if constraintErr := checkDecodedLength(opts, sd78d83_19, "37.4", "classmarkInformation", "SIZE (1..2)", len(v.ClassmarkInformation)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode handoverPriority
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "handoverPriority", content[offset:])
				decodedTag_handoverpriority, n_handoverpriority, rawVal_handoverpriority, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "handoverPriority", "decoding", false)
				}
				if decodedTag_handoverpriority.Class != tag.ClassContextSpecific || decodedTag_handoverpriority.Number != 11 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_handoverpriority), "handoverPriority", "decoding", false)
				}
				decVal_handoverpriority, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_handoverpriority.Constructed, rawVal_handoverpriority, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "handoverPriority", "decoding", false)
				}
				tmp_handoverpriority := HandoverPriority(decVal_handoverpriority)
				v.HandoverPriority = &tmp_handoverpriority
				if offset < 0 || offset >
					len(content) || n_handoverpriority < 0 || n_handoverpriority > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_handoverpriority
				if len(*v.HandoverPriority) < 1 || len(*v.HandoverPriority) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_19, "37.4", "handoverPriority", "SIZE (1)", len(*v.HandoverPriority)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode kc
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "kc", content[offset:])
				decodedTag_kc, n_kc, rawVal_kc, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "kc", "decoding", false)
				}
				if decodedTag_kc.Class != tag.ClassContextSpecific || decodedTag_kc.Number != 12 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_kc), "kc", "decoding", false)
				}
				decVal_kc, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_kc.Constructed, rawVal_kc, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "kc", "decoding", false)
				}
				tmp_kc := Kc(decVal_kc)
				v.Kc = &tmp_kc
				if offset < 0 || offset >
					len(content) || n_kc < 0 || n_kc > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_kc
				if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
					if constraintErr := checkDecodedLength(opts, sd78d83_19, "37.4", "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PerformHandoverArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes PerformHandoverResult to BER format.
func (v *PerformHandoverResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PerformHandoverResult receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PerformHandoverResult).MarshalBER, (*PerformHandoverResult).marshalBER, 3)

}
func (v *PerformHandoverResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_20, "37.4", "handoverNumber", "SIZE (1..10)", len(v.HandoverNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_20, "37.4", "handoverNumber", "SIZE (1..20)", len(v.HandoverNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_handovernumber, encodeErr_enc_handovernumber := ber.EncodeOctetString([]byte(v.HandoverNumber))
	if encodeErr_enc_handovernumber != nil {
		return nil, qualifyBERError(encodeErr_enc_handovernumber, "handoverNumber", "encoding", false)
	}
	children = append(children, enc_handovernumber...)
	enc_accesssignalinfo, err := v.AccessSignalInfo.MarshalBER(ber.ChildEncodeOptions(opts, "accessSignalInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "accessSignalInfo", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_accesssignalinfo)
	children = append(children, enc_accesssignalinfo...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PerformHandoverResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PerformHandoverResult to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PerformHandoverResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PerformHandoverResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_20, "37.4", "handoverNumber", "SIZE (1..10)", len(v.HandoverNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_20, "37.4", "handoverNumber", "SIZE (1..20)", len(v.HandoverNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_handovernumber, encodeErr_enc_handovernumber := ber.EncodeOctetString([]byte(v.HandoverNumber))
	if encodeErr_enc_handovernumber != nil {
		return nil, qualifyBERError(encodeErr_enc_handovernumber, "handoverNumber", "encoding", true)
	}
	children = append(children, enc_handovernumber...)
	enc_accesssignalinfo, err := v.AccessSignalInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "accessSignalInfo", "encoding", true)
	}
	children = append(children, enc_accesssignalinfo...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PerformHandoverResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PerformHandoverResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PerformHandoverResult from BER/DER format.
func (destination *PerformHandoverResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PerformHandoverResult destination is nil", ber.ErrInvalidValue)
	}
	v := new(PerformHandoverResult)

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
			var probe PerformHandoverResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_20, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PerformHandoverResult{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PerformHandoverResult).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PerformHandoverResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PerformHandoverResult", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode handoverNumber
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field handoverNumber", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "handoverNumber", content[offset:])
		val_handovernumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "handoverNumber", "decoding", false)
		}
		v.HandoverNumber = IsdnAddressString(val_handovernumber)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_20, "37.4", "handoverNumber", "SIZE (1..10)", len(v.HandoverNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.HandoverNumber) < 1 || len(v.HandoverNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_20, "37.4", "handoverNumber", "SIZE (1..20)", len(v.HandoverNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode accessSignalInfo
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field accessSignalInfo", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "accessSignalInfo", content[offset:])
		// Decode nested SEQUENCE (ExternalSignalInfo)
		_, n_accesssignalinfo, _, tlvErr_accesssignalinfo := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_accesssignalinfo != nil {
			return qualifyBERError(tlvErr_accesssignalinfo, "accessSignalInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_accesssignalinfo < 0 || n_accesssignalinfo >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.AccessSignalInfo.UnmarshalBER(content[offset:offset+n_accesssignalinfo], ber.ChildDecodeOptions(opts, "accessSignalInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "accessSignalInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_accesssignalinfo < 0 || n_accesssignalinfo >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_accesssignalinfo
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PerformHandoverResult", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes PerformSubsequentHandoverArgument to BER format.
func (v *PerformSubsequentHandoverArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: PerformSubsequentHandoverArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*PerformSubsequentHandoverArgument).MarshalBER, (*PerformSubsequentHandoverArgument).marshalBER, 3)

}
func (v *PerformSubsequentHandoverArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
		if constraintErr := checkEncodedLength(opts, sd78d83_21, "37.4", "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(v.TargetCellId))
	if encodeErr_enc_targetcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", false)
	}
	children = append(children, enc_targetcellid...)
	if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
		if constraintErr := checkEncodedLength(opts, sd78d83_21, "37.4", "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servingcellid, encodeErr_enc_servingcellid := ber.EncodeOctetString([]byte(v.ServingCellId))
	if encodeErr_enc_servingcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_servingcellid, "servingCellId", "encoding", false)
	}
	children = append(children, enc_servingcellid...)
	if len(v.TargetMscNumber) < 1 || len(v.TargetMscNumber) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_21, "37.4", "targetMscNumber", "SIZE (1..10)", len(v.TargetMscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TargetMscNumber) < 1 || len(v.TargetMscNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_21, "37.4", "targetMscNumber", "SIZE (1..20)", len(v.TargetMscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetmscnumber, encodeErr_enc_targetmscnumber := ber.EncodeOctetString([]byte(v.TargetMscNumber))
	if encodeErr_enc_targetmscnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_targetmscnumber, "targetMscNumber", "encoding", false)
	}
	children = append(children, enc_targetmscnumber...)
	if v.ClassmarkInformation != nil {
		if len(*v.ClassmarkInformation) < 1 || len(*v.ClassmarkInformation) > 2 {
			if constraintErr := checkEncodedLength(opts, sd78d83_21, "37.4", "classmarkInformation", "SIZE (1..2)", len(*v.ClassmarkInformation)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_classmarkinformation, encodeErr_enc_classmarkinformation := ber.EncodeOctetString([]byte(*v.ClassmarkInformation))
		if encodeErr_enc_classmarkinformation != nil {
			return nil, qualifyBERError(encodeErr_enc_classmarkinformation, "classmarkInformation", "encoding", false)
		}
		retagged_enc_classmarkinformation, tagErr_enc_classmarkinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_classmarkinformation)
		if tagErr_enc_classmarkinformation != nil {
			return nil, qualifyBERError(tagErr_enc_classmarkinformation, "classmarkInformation", "encoding", false)
		}
		enc_classmarkinformation = retagged_enc_classmarkinformation
		children = append(children, enc_classmarkinformation...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *PerformSubsequentHandoverArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes PerformSubsequentHandoverArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *PerformSubsequentHandoverArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: PerformSubsequentHandoverArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
		if constraintErr := checkEncodedLength(nil, sd78d83_21, "37.4", "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetcellid, encodeErr_enc_targetcellid := ber.EncodeOctetString([]byte(v.TargetCellId))
	if encodeErr_enc_targetcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetcellid, "targetCellId", "encoding", true)
	}
	children = append(children, enc_targetcellid...)
	if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
		if constraintErr := checkEncodedLength(nil, sd78d83_21, "37.4", "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servingcellid, encodeErr_enc_servingcellid := ber.EncodeOctetString([]byte(v.ServingCellId))
	if encodeErr_enc_servingcellid != nil {
		return nil, qualifyBERError(encodeErr_enc_servingcellid, "servingCellId", "encoding", true)
	}
	children = append(children, enc_servingcellid...)
	if len(v.TargetMscNumber) < 1 || len(v.TargetMscNumber) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_21, "37.4", "targetMscNumber", "SIZE (1..10)", len(v.TargetMscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.TargetMscNumber) < 1 || len(v.TargetMscNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_21, "37.4", "targetMscNumber", "SIZE (1..20)", len(v.TargetMscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetmscnumber, encodeErr_enc_targetmscnumber := ber.EncodeOctetString([]byte(v.TargetMscNumber))
	if encodeErr_enc_targetmscnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_targetmscnumber, "targetMscNumber", "encoding", true)
	}
	children = append(children, enc_targetmscnumber...)
	if v.ClassmarkInformation != nil {
		if len(*v.ClassmarkInformation) < 1 || len(*v.ClassmarkInformation) > 2 {
			if constraintErr := checkEncodedLength(nil, sd78d83_21, "37.4", "classmarkInformation", "SIZE (1..2)", len(*v.ClassmarkInformation)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_classmarkinformation, encodeErr_enc_classmarkinformation := ber.EncodeOctetString([]byte(*v.ClassmarkInformation))
		if encodeErr_enc_classmarkinformation != nil {
			return nil, qualifyBERError(encodeErr_enc_classmarkinformation, "classmarkInformation", "encoding", true)
		}
		retagged_enc_classmarkinformation, tagErr_enc_classmarkinformation := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_classmarkinformation)
		if tagErr_enc_classmarkinformation != nil {
			return nil, qualifyBERError(tagErr_enc_classmarkinformation, "classmarkInformation", "encoding", true)
		}
		enc_classmarkinformation = retagged_enc_classmarkinformation
		children = append(children, enc_classmarkinformation...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding PerformSubsequentHandoverArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *PerformSubsequentHandoverArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes PerformSubsequentHandoverArgument from BER/DER format.
func (destination *PerformSubsequentHandoverArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: PerformSubsequentHandoverArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(PerformSubsequentHandoverArgument)

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
			var probe PerformSubsequentHandoverArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_21, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = PerformSubsequentHandoverArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*PerformSubsequentHandoverArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding PerformSubsequentHandoverArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "PerformSubsequentHandoverArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode targetCellId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field targetCellId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "targetCellId", content[offset:])
		val_targetcellid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "targetCellId", "decoding", false)
		}
		v.TargetCellId = GlobalCellId(val_targetcellid)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.TargetCellId) < 5 || len(v.TargetCellId) > 7 {
			if constraintErr := checkDecodedLength(opts, sd78d83_21, "37.4", "targetCellId", "SIZE (5..7)", len(v.TargetCellId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode servingCellId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field servingCellId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "servingCellId", content[offset:])
		val_servingcellid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "servingCellId", "decoding", false)
		}
		v.ServingCellId = GlobalCellId(val_servingcellid)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.ServingCellId) < 5 || len(v.ServingCellId) > 7 {
			if constraintErr := checkDecodedLength(opts, sd78d83_21, "37.4", "servingCellId", "SIZE (5..7)", len(v.ServingCellId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode targetMscNumber
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field targetMscNumber", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "targetMscNumber", content[offset:])
		val_targetmscnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "targetMscNumber", "decoding", false)
		}
		v.TargetMscNumber = IsdnAddressString(val_targetmscnumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.TargetMscNumber) < 1 || len(v.TargetMscNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_21, "37.4", "targetMscNumber", "SIZE (1..10)", len(v.TargetMscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.TargetMscNumber) < 1 || len(v.TargetMscNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_21, "37.4", "targetMscNumber", "SIZE (1..20)", len(v.TargetMscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode classmarkInformation
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "classmarkInformation", content[offset:])
				decodedTag_classmarkinformation, n_classmarkinformation, rawVal_classmarkinformation, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "classmarkInformation", "decoding", false)
				}
				if decodedTag_classmarkinformation.Class != tag.ClassContextSpecific || decodedTag_classmarkinformation.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_classmarkinformation), "classmarkInformation", "decoding", false)
				}
				decVal_classmarkinformation, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_classmarkinformation.Constructed, rawVal_classmarkinformation, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "classmarkInformation", "decoding", false)
				}
				tmp_classmarkinformation := ClassmarkInformation(decVal_classmarkinformation)
				v.ClassmarkInformation = &tmp_classmarkinformation
				if offset < 0 || offset >
					len(content) || n_classmarkinformation < 0 || n_classmarkinformation > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_classmarkinformation
				if len(*v.ClassmarkInformation) < 1 || len(*v.ClassmarkInformation) > 2 {
					if constraintErr := checkDecodedLength(opts, sd78d83_21, "37.4", "classmarkInformation", "SIZE (1..2)", len(*v.ClassmarkInformation)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "PerformSubsequentHandoverArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ProcessAccessRequestArgument to BER format.
func (v *ProcessAccessRequestArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ProcessAccessRequestArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ProcessAccessRequestArgument).MarshalBER, (*ProcessAccessRequestArgument).marshalBER, 3)

}
func (v *ProcessAccessRequestArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_subscriberid, err := v.SubscriberId.MarshalBER(ber.ChildEncodeOptions(opts, "subscriberId")...)
	if err != nil {
		return nil, qualifyBERError(err, "subscriberId", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_subscriberid)
	children = append(children, enc_subscriberid...)
	if int64(v.CmServiceType) != 1 && int64(v.CmServiceType) != 2 && int64(v.CmServiceType) != 4 && int64(v.CmServiceType) != 8 && int64(v.CmServiceType) != 9 && int64(v.CmServiceType) != 10 {
		if constraintErr := checkEncodedValue(opts, sd78d83_22, "15", "cmServiceType", "ENUMERATED {1, 2, 4, 8, 9, 10}", ber.ObserveInteger(int64(v.CmServiceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cmservicetype := ber.EncodeEnumerated(int64(v.CmServiceType))
	children = append(children, enc_cmservicetype...)
	if len(v.AccessConnectionStatus) < 1 || len(v.AccessConnectionStatus) > 1 {
		if constraintErr := checkEncodedLength(opts, sd78d83_22, "37.4", "accessConnectionStatus", "SIZE (1)", len(v.AccessConnectionStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_accessconnectionstatus, encodeErr_enc_accessconnectionstatus := ber.EncodeOctetString([]byte(v.AccessConnectionStatus))
	if encodeErr_enc_accessconnectionstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_accessconnectionstatus, "accessConnectionStatus", "encoding", false)
	}
	children = append(children, enc_accessconnectionstatus...)
	if len(v.Cksn) < 1 || len(v.Cksn) > 1 {
		if constraintErr := checkEncodedLength(opts, sd78d83_22, "37.4", "cksn", "SIZE (1)", len(v.Cksn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cksn, encodeErr_enc_cksn := ber.EncodeOctetString([]byte(v.Cksn))
	if encodeErr_enc_cksn != nil {
		return nil, qualifyBERError(encodeErr_enc_cksn, "cksn", "encoding", false)
	}
	children = append(children, enc_cksn...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ProcessAccessRequestArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ProcessAccessRequestArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ProcessAccessRequestArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ProcessAccessRequestArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_subscriberid, err := v.SubscriberId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "subscriberId", "encoding", true)
	}
	children = append(children, enc_subscriberid...)
	if int64(v.CmServiceType) != 1 && int64(v.CmServiceType) != 2 && int64(v.CmServiceType) != 4 && int64(v.CmServiceType) != 8 && int64(v.CmServiceType) != 9 && int64(v.CmServiceType) != 10 {
		if constraintErr := checkEncodedValue(nil, sd78d83_22, "15", "cmServiceType", "ENUMERATED {1, 2, 4, 8, 9, 10}", ber.ObserveInteger(int64(v.CmServiceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cmservicetype := ber.EncodeEnumerated(int64(v.CmServiceType))
	children = append(children, enc_cmservicetype...)
	if len(v.AccessConnectionStatus) < 1 || len(v.AccessConnectionStatus) > 1 {
		if constraintErr := checkEncodedLength(nil, sd78d83_22, "37.4", "accessConnectionStatus", "SIZE (1)", len(v.AccessConnectionStatus)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_accessconnectionstatus, encodeErr_enc_accessconnectionstatus := ber.EncodeOctetString([]byte(v.AccessConnectionStatus))
	if encodeErr_enc_accessconnectionstatus != nil {
		return nil, qualifyBERError(encodeErr_enc_accessconnectionstatus, "accessConnectionStatus", "encoding", true)
	}
	children = append(children, enc_accessconnectionstatus...)
	if len(v.Cksn) < 1 || len(v.Cksn) > 1 {
		if constraintErr := checkEncodedLength(nil, sd78d83_22, "37.4", "cksn", "SIZE (1)", len(v.Cksn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cksn, encodeErr_enc_cksn := ber.EncodeOctetString([]byte(v.Cksn))
	if encodeErr_enc_cksn != nil {
		return nil, qualifyBERError(encodeErr_enc_cksn, "cksn", "encoding", true)
	}
	children = append(children, enc_cksn...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ProcessAccessRequestArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ProcessAccessRequestArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ProcessAccessRequestArgument from BER/DER format.
func (destination *ProcessAccessRequestArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ProcessAccessRequestArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(ProcessAccessRequestArgument)

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
			var probe ProcessAccessRequestArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_22, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ProcessAccessRequestArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ProcessAccessRequestArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ProcessAccessRequestArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProcessAccessRequestArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode subscriberId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field subscriberId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "subscriberId", content[offset:])
		// Decode nested CHOICE (SubscriberId)
		_, n_subscriberid, _, tlvErr_subscriberid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_subscriberid != nil {
			return qualifyBERError(tlvErr_subscriberid, "subscriberId", "decoding", false)
		}
		if offset > len(content) || n_subscriberid < 0 || n_subscriberid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.SubscriberId.UnmarshalBER(content[offset:offset+n_subscriberid], ber.ChildDecodeOptions(opts, "subscriberId")...); unmErr != nil {
			return qualifyBERError(unmErr, "subscriberId", "decoding", false)
		}
		if offset > len(content) || n_subscriberid < 0 || n_subscriberid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_subscriberid
	}
	// Decode cmServiceType
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cmServiceType", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cmServiceType", content[offset:])
		val_cmservicetype, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cmServiceType", "decoding", false)
		}
		v.CmServiceType = CmServiceType(val_cmservicetype)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.CmServiceType) != 1 && int64(v.CmServiceType) != 2 && int64(v.CmServiceType) != 4 && int64(v.CmServiceType) != 8 && int64(v.CmServiceType) != 9 && int64(v.CmServiceType) != 10 {
			if constraintErr := checkDecodedValue(opts, sd78d83_22, "15", "cmServiceType", "ENUMERATED {1, 2, 4, 8, 9, 10}", ber.ObserveInteger(int64(v.CmServiceType))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode accessConnectionStatus
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field accessConnectionStatus", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "accessConnectionStatus", content[offset:])
		val_accessconnectionstatus, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "accessConnectionStatus", "decoding", false)
		}
		v.AccessConnectionStatus = AccessConnectionStatus(val_accessconnectionstatus)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.AccessConnectionStatus) < 1 || len(v.AccessConnectionStatus) > 1 {
			if constraintErr := checkDecodedLength(opts, sd78d83_22, "37.4", "accessConnectionStatus", "SIZE (1)", len(v.AccessConnectionStatus)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cksn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cksn", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cksn", content[offset:])
		val_cksn, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cksn", "decoding", false)
		}
		v.Cksn = CKSN(val_cksn)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Cksn) < 1 || len(v.Cksn) > 1 {
			if constraintErr := checkDecodedLength(opts, sd78d83_22, "37.4", "cksn", "SIZE (1)", len(v.Cksn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProcessAccessRequestArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ProcessAccessRequestResult to BER format.
func (v *ProcessAccessRequestResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ProcessAccessRequestResult receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ProcessAccessRequestResult).MarshalBER, (*ProcessAccessRequestResult).marshalBER, 3)

}
func (v *ProcessAccessRequestResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, sd78d83_23, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_23, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_23, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.MsIsdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", false)
		}
		children = append(children, enc_msisdn...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ProcessAccessRequestResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ProcessAccessRequestResult to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ProcessAccessRequestResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ProcessAccessRequestResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, sd78d83_23, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkEncodedLength(nil, sd78d83_23, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_23, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.MsIsdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", true)
		}
		children = append(children, enc_msisdn...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ProcessAccessRequestResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ProcessAccessRequestResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ProcessAccessRequestResult from BER/DER format.
func (destination *ProcessAccessRequestResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ProcessAccessRequestResult destination is nil", ber.ErrInvalidValue)
	}
	v := new(ProcessAccessRequestResult)

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
			var probe ProcessAccessRequestResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_23, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ProcessAccessRequestResult{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ProcessAccessRequestResult).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ProcessAccessRequestResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProcessAccessRequestResult", Cause: ber.ErrExtraData}
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
		if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, sd78d83_23, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode msIsdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "msIsdn", content[offset:])
				val_msisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msIsdn", "decoding", false)
				}
				tmp_msisdn := IsdnAddressString(val_msisdn)
				v.MsIsdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
					if constraintErr := checkDecodedLength(opts, sd78d83_23, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_23, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProcessAccessRequestResult", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ProvideRoamingNumberArgument to BER format.
func (v *ProvideRoamingNumberArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ProvideRoamingNumberArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ProvideRoamingNumberArgument).MarshalBER, (*ProvideRoamingNumberArgument).marshalBER, 3)

}
func (v *ProvideRoamingNumberArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, sd78d83_24, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
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
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_24, "37.4", "mscNumber", "SIZE (1..10)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_24, "37.4", "mscNumber", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscnumber, encodeErr_enc_mscnumber := ber.EncodeOctetString([]byte(*v.MscNumber))
		if encodeErr_enc_mscnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_mscnumber, "mscNumber", "encoding", false)
		}
		retagged_enc_mscnumber, tagErr_enc_mscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mscnumber)
		if tagErr_enc_mscnumber != nil {
			return nil, qualifyBERError(tagErr_enc_mscnumber, "mscNumber", "encoding", false)
		}
		enc_mscnumber = retagged_enc_mscnumber
		children = append(children, enc_mscnumber...)
	}
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_24, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_24, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.MsIsdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", false)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msIsdn", "encoding", false)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.PreviousRoamingNumber != nil {
		if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_24, "37.4", "previousRoamingNumber", "SIZE (1..10)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_24, "37.4", "previousRoamingNumber", "SIZE (1..20)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
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
	if v.LMsId != nil {
		if len(*v.LMsId) < 4 || len(*v.LMsId) > 4 {
			if constraintErr := checkEncodedLength(opts, sd78d83_24, "37.4", "lMsId", "SIZE (4)", len(*v.LMsId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsid, encodeErr_enc_lmsid := ber.EncodeOctetString([]byte(*v.LMsId))
		if encodeErr_enc_lmsid != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsid, "lMsId", "encoding", false)
		}
		retagged_enc_lmsid, tagErr_enc_lmsid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lmsid)
		if tagErr_enc_lmsid != nil {
			return nil, qualifyBERError(tagErr_enc_lmsid, "lMsId", "encoding", false)
		}
		enc_lmsid = retagged_enc_lmsid
		children = append(children, enc_lmsid...)
	}
	if v.GSMBearerCapability != nil {
		enc_gsmbearercapability, err := v.GSMBearerCapability.MarshalBER(ber.ChildEncodeOptions(opts, "gSM-BearerCapability")...)
		if err != nil {
			return nil, qualifyBERError(err, "gSM-BearerCapability", "encoding", false)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, qualifyBERError(tagErr_enc_gsmbearercapability, "gSM-BearerCapability", "encoding", false)
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
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ProvideRoamingNumberArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ProvideRoamingNumberArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ProvideRoamingNumberArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ProvideRoamingNumberArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, sd78d83_24, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
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
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 10 {
			if constraintErr := checkEncodedLength(nil, sd78d83_24, "37.4", "mscNumber", "SIZE (1..10)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_24, "37.4", "mscNumber", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_mscnumber, encodeErr_enc_mscnumber := ber.EncodeOctetString([]byte(*v.MscNumber))
		if encodeErr_enc_mscnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_mscnumber, "mscNumber", "encoding", true)
		}
		retagged_enc_mscnumber, tagErr_enc_mscnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_mscnumber)
		if tagErr_enc_mscnumber != nil {
			return nil, qualifyBERError(tagErr_enc_mscnumber, "mscNumber", "encoding", true)
		}
		enc_mscnumber = retagged_enc_mscnumber
		children = append(children, enc_mscnumber...)
	}
	if v.MsIsdn != nil {
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
			if constraintErr := checkEncodedLength(nil, sd78d83_24, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_24, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(*v.MsIsdn))
		if encodeErr_enc_msisdn != nil {
			return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", true)
		}
		retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_msisdn)
		if tagErr_enc_msisdn != nil {
			return nil, qualifyBERError(tagErr_enc_msisdn, "msIsdn", "encoding", true)
		}
		enc_msisdn = retagged_enc_msisdn
		children = append(children, enc_msisdn...)
	}
	if v.PreviousRoamingNumber != nil {
		if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 10 {
			if constraintErr := checkEncodedLength(nil, sd78d83_24, "37.4", "previousRoamingNumber", "SIZE (1..10)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_24, "37.4", "previousRoamingNumber", "SIZE (1..20)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
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
	if v.LMsId != nil {
		if len(*v.LMsId) < 4 || len(*v.LMsId) > 4 {
			if constraintErr := checkEncodedLength(nil, sd78d83_24, "37.4", "lMsId", "SIZE (4)", len(*v.LMsId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsid, encodeErr_enc_lmsid := ber.EncodeOctetString([]byte(*v.LMsId))
		if encodeErr_enc_lmsid != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsid, "lMsId", "encoding", true)
		}
		retagged_enc_lmsid, tagErr_enc_lmsid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lmsid)
		if tagErr_enc_lmsid != nil {
			return nil, qualifyBERError(tagErr_enc_lmsid, "lMsId", "encoding", true)
		}
		enc_lmsid = retagged_enc_lmsid
		children = append(children, enc_lmsid...)
	}
	if v.GSMBearerCapability != nil {
		enc_gsmbearercapability, err := v.GSMBearerCapability.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "gSM-BearerCapability", "encoding", true)
		}
		retagged_enc_gsmbearercapability, tagErr_enc_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_gsmbearercapability)
		if tagErr_enc_gsmbearercapability != nil {
			return nil, qualifyBERError(tagErr_enc_gsmbearercapability, "gSM-BearerCapability", "encoding", true)
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ProvideRoamingNumberArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ProvideRoamingNumberArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ProvideRoamingNumberArgument from BER/DER format.
func (destination *ProvideRoamingNumberArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ProvideRoamingNumberArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(ProvideRoamingNumberArgument)

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
			var probe ProvideRoamingNumberArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_24, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ProvideRoamingNumberArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ProvideRoamingNumberArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ProvideRoamingNumberArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ProvideRoamingNumberArgument", Cause: ber.ErrExtraData}
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
		if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, sd78d83_24, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode mscNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "mscNumber", content[offset:])
				decodedTag_mscnumber, n_mscnumber, rawVal_mscnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "mscNumber", "decoding", false)
				}
				if decodedTag_mscnumber.Class != tag.ClassContextSpecific || decodedTag_mscnumber.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_mscnumber), "mscNumber", "decoding", false)
				}
				decVal_mscnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_mscnumber.Constructed, rawVal_mscnumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "mscNumber", "decoding", false)
				}
				tmp_mscnumber := IsdnAddressString(decVal_mscnumber)
				v.MscNumber = &tmp_mscnumber
				if offset < 0 || offset >
					len(content) || n_mscnumber < 0 || n_mscnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_mscnumber
				if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 10 {
					if constraintErr := checkDecodedLength(opts, sd78d83_24, "37.4", "mscNumber", "SIZE (1..10)", len(*v.MscNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.MscNumber) < 1 || len(*v.MscNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_24, "37.4", "mscNumber", "SIZE (1..20)", len(*v.MscNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode msIsdn
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "msIsdn", content[offset:])
				decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "msIsdn", "decoding", false)
				}
				if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_msisdn), "msIsdn", "decoding", false)
				}
				decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "msIsdn", "decoding", false)
				}
				tmp_msisdn := IsdnAddressString(decVal_msisdn)
				v.MsIsdn = &tmp_msisdn
				if offset < 0 || offset >
					len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_msisdn
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 10 {
					if constraintErr := checkDecodedLength(opts, sd78d83_24, "37.4", "msIsdn", "SIZE (1..10)", len(*v.MsIsdn)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.MsIsdn) < 1 || len(*v.MsIsdn) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_24, "37.4", "msIsdn", "SIZE (1..20)", len(*v.MsIsdn)); constraintErr != nil {
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
				tmp_previousroamingnumber := IsdnAddressString(decVal_previousroamingnumber)
				v.PreviousRoamingNumber = &tmp_previousroamingnumber
				if offset < 0 || offset >
					len(content) || n_previousroamingnumber < 0 || n_previousroamingnumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_previousroamingnumber
				if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 10 {
					if constraintErr := checkDecodedLength(opts, sd78d83_24, "37.4", "previousRoamingNumber", "SIZE (1..10)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.PreviousRoamingNumber) < 1 || len(*v.PreviousRoamingNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_24, "37.4", "previousRoamingNumber", "SIZE (1..20)", len(*v.PreviousRoamingNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lMsId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "lMsId", content[offset:])
				decodedTag_lmsid, n_lmsid, rawVal_lmsid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lMsId", "decoding", false)
				}
				if decodedTag_lmsid.Class != tag.ClassContextSpecific || decodedTag_lmsid.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_lmsid), "lMsId", "decoding", false)
				}
				decVal_lmsid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lmsid.Constructed, rawVal_lmsid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lMsId", "decoding", false)
				}
				tmp_lmsid := LMsId(decVal_lmsid)
				v.LMsId = &tmp_lmsid
				if offset < 0 || offset >
					len(content) || n_lmsid < 0 || n_lmsid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lmsid
				if len(*v.LMsId) < 4 || len(*v.LMsId) > 4 {
					if constraintErr := checkDecodedLength(opts, sd78d83_24, "37.4", "lMsId", "SIZE (4)", len(*v.LMsId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode gSM-BearerCapability
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "gSM-BearerCapability", content[offset:])
				decodedTag_gsmbearercapability, n_gsmbearercapability, rawVal_gsmbearercapability, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "gSM-BearerCapability", "decoding", false)
				}
				if decodedTag_gsmbearercapability.Class != tag.ClassContextSpecific || decodedTag_gsmbearercapability.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_gsmbearercapability), "gSM-BearerCapability", "decoding", false)
				}
				if decodedTag_gsmbearercapability.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_gsmbearercapability), "gSM-BearerCapability", "decoding", false)
				}
				_ = rawVal_gsmbearercapability
				if offset < 0 || offset >
					len(content) || n_gsmbearercapability < 0 || n_gsmbearercapability >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_gsmbearercapability, reconstructionErr_gsmbearercapability := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_gsmbearercapability])
				if reconstructionErr_gsmbearercapability != nil {
					return qualifyBERError(reconstructionErr_gsmbearercapability, "gSM-BearerCapability", "decoding", false)
				}
				var dec_gsmbearercapability ExternalSignalInfo
				if unmErr := dec_gsmbearercapability.UnmarshalBER(reconstructed_gsmbearercapability, ber.ChildDecodeOptions(opts, "gSM-BearerCapability")...); unmErr != nil {
					return qualifyBERError(unmErr, "gSM-BearerCapability", "decoding", false)
				}
				v.GSMBearerCapability = &dec_gsmbearercapability
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
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo > len(
					content[offset:]) {
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
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_networksignalinfo
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ProvideRoamingNumberArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes RegisterChargingInformationArgument to BER format.
func (v *RegisterChargingInformationArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RegisterChargingInformationArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RegisterChargingInformationArgument).MarshalBER, (*RegisterChargingInformationArgument).marshalBER, 3)

}
func (v *RegisterChargingInformationArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", false)
	}
	children = append(children, enc_msisdn...)
	if len(v.MscNumber) < 1 || len(v.MscNumber) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "mscNumber", "SIZE (1..10)", len(v.MscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MscNumber) < 1 || len(v.MscNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "mscNumber", "SIZE (1..20)", len(v.MscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mscnumber, encodeErr_enc_mscnumber := ber.EncodeOctetString([]byte(v.MscNumber))
	if encodeErr_enc_mscnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_mscnumber, "mscNumber", "encoding", false)
	}
	children = append(children, enc_mscnumber...)
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	if len(v.CallReference) < 1 || len(v.CallReference) > 3 {
		if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "callReference", "SIZE (1..3)", len(v.CallReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callreference, encodeErr_enc_callreference := ber.EncodeOctetString([]byte(v.CallReference))
	if encodeErr_enc_callreference != nil {
		return nil, qualifyBERError(encodeErr_enc_callreference, "callReference", "encoding", false)
	}
	children = append(children, enc_callreference...)
	if int64(v.CallType) != 0 && int64(v.CallType) != 1 && int64(v.CallType) != 2 && int64(v.CallType) != 3 && int64(v.CallType) != 4 {
		if constraintErr := checkEncodedValue(opts, sd78d83_25, "15", "callType", "ENUMERATED {0, 1, 2, 3, 4}", ber.ObserveInteger(int64(v.CallType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_calltype := ber.EncodeEnumerated(int64(v.CallType))
	children = append(children, enc_calltype...)
	if int64(v.CallStatus) != 0 && int64(v.CallStatus) != 1 && int64(v.CallStatus) != 2 && int64(v.CallStatus) != 4 && int64(v.CallStatus) != 5 && int64(v.CallStatus) != 6 && int64(v.CallStatus) != 7 && int64(v.CallStatus) != 8 && int64(v.CallStatus) != 9 && int64(v.CallStatus) != 10 && int64(v.CallStatus) != 11 && int64(v.CallStatus) != 12 && int64(v.CallStatus) != 13 {
		if constraintErr := checkEncodedValue(opts, sd78d83_25, "15", "callStatus", "ENUMERATED {0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}", ber.ObserveInteger(int64(v.CallStatus))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callstatus := ber.EncodeEnumerated(int64(v.CallStatus))
	children = append(children, enc_callstatus...)
	if len((v.CallDateTime).String()) < 14 || len((v.CallDateTime).String()) > 24 {
		if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "callDateTime", "SIZE (14..24)", len((v.CallDateTime).String())); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_calldatetime, encodeErr_enc_calldatetime := encodeEditionGeneralizedTime(v.CallDateTime, sd78d83_25, "callDateTime")
	if encodeErr_enc_calldatetime != nil {
		if _, timeViolation := encodeErr_enc_calldatetime.(*ber.ValidationError); timeViolation {
			return nil, encodeErr_enc_calldatetime
		}

		return nil, qualifyBERError(encodeErr_enc_calldatetime, "callDateTime", "encoding", false)
	}
	children = append(children, enc_calldatetime...)
	if !(int64(v.CallDuration) >= 0 && int64(v.CallDuration) <= 16777215) {
		if constraintErr := checkEncodedValue(opts, sd78d83_25, "37.3", "callDuration", "(0..16777215)", ber.ObserveInteger(int64(v.CallDuration))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callduration := ber.EncodeInteger(int64(v.CallDuration))
	children = append(children, enc_callduration...)
	if v.BearerServiceCode != nil {
		if len(*v.BearerServiceCode) < 1 || len(*v.BearerServiceCode) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "bearerServiceCode", "SIZE (1)", len(*v.BearerServiceCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservicecode, encodeErr_enc_bearerservicecode := ber.EncodeOctetString([]byte(*v.BearerServiceCode))
		if encodeErr_enc_bearerservicecode != nil {
			return nil, qualifyBERError(encodeErr_enc_bearerservicecode, "bearerServiceCode", "encoding", false)
		}
		retagged_enc_bearerservicecode, tagErr_enc_bearerservicecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_bearerservicecode)
		if tagErr_enc_bearerservicecode != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservicecode, "bearerServiceCode", "encoding", false)
		}
		enc_bearerservicecode = retagged_enc_bearerservicecode
		children = append(children, enc_bearerservicecode...)
	}
	if v.TeleserviceCode != nil {
		if len(*v.TeleserviceCode) < 1 || len(*v.TeleserviceCode) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "teleserviceCode", "SIZE (1)", len(*v.TeleserviceCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicecode, encodeErr_enc_teleservicecode := ber.EncodeOctetString([]byte(*v.TeleserviceCode))
		if encodeErr_enc_teleservicecode != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservicecode, "teleserviceCode", "encoding", false)
		}
		retagged_enc_teleservicecode, tagErr_enc_teleservicecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_teleservicecode)
		if tagErr_enc_teleservicecode != nil {
			return nil, qualifyBERError(tagErr_enc_teleservicecode, "teleserviceCode", "encoding", false)
		}
		enc_teleservicecode = retagged_enc_teleservicecode
		children = append(children, enc_teleservicecode...)
	}
	if v.CalledNumber != nil {
		if len(*v.CalledNumber) < 1 || len(*v.CalledNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "calledNumber", "SIZE (1..10)", len(*v.CalledNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.CalledNumber) < 1 || len(*v.CalledNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "calledNumber", "SIZE (1..20)", len(*v.CalledNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callednumber, encodeErr_enc_callednumber := ber.EncodeOctetString([]byte(*v.CalledNumber))
		if encodeErr_enc_callednumber != nil {
			return nil, qualifyBERError(encodeErr_enc_callednumber, "calledNumber", "encoding", false)
		}
		retagged_enc_callednumber, tagErr_enc_callednumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_callednumber)
		if tagErr_enc_callednumber != nil {
			return nil, qualifyBERError(tagErr_enc_callednumber, "calledNumber", "encoding", false)
		}
		enc_callednumber = retagged_enc_callednumber
		children = append(children, enc_callednumber...)
	}
	if v.CallingNumber != nil {
		if len(*v.CallingNumber) < 1 || len(*v.CallingNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "callingNumber", "SIZE (1..10)", len(*v.CallingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.CallingNumber) < 1 || len(*v.CallingNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "callingNumber", "SIZE (1..20)", len(*v.CallingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callingnumber, encodeErr_enc_callingnumber := ber.EncodeOctetString([]byte(*v.CallingNumber))
		if encodeErr_enc_callingnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_callingnumber, "callingNumber", "encoding", false)
		}
		retagged_enc_callingnumber, tagErr_enc_callingnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_callingnumber)
		if tagErr_enc_callingnumber != nil {
			return nil, qualifyBERError(tagErr_enc_callingnumber, "callingNumber", "encoding", false)
		}
		enc_callingnumber = retagged_enc_callingnumber
		children = append(children, enc_callingnumber...)
	}
	if v.PacketDataVolume != nil {
		if !(int64(*v.PacketDataVolume) >= 1 && int64(*v.PacketDataVolume) <= 100) {
			if constraintErr := checkEncodedValue(opts, sd78d83_25, "37.3", "packetDataVolume", "(1..100)", ber.ObserveInteger(int64(*v.PacketDataVolume))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_packetdatavolume := ber.EncodeInteger(int64(*v.PacketDataVolume))
		retagged_enc_packetdatavolume, tagErr_enc_packetdatavolume := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_packetdatavolume)
		if tagErr_enc_packetdatavolume != nil {
			return nil, qualifyBERError(tagErr_enc_packetdatavolume, "packetDataVolume", "encoding", false)
		}
		enc_packetdatavolume = retagged_enc_packetdatavolume
		children = append(children, enc_packetdatavolume...)
	}
	if v.ChargingUnit != nil {
		if int64(*v.ChargingUnit) != 0 {
			if constraintErr := checkEncodedValue(opts, sd78d83_25, "15", "chargingUnit", "ENUMERATED {0}", ber.ObserveInteger(int64(*v.ChargingUnit))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_chargingunit := ber.EncodeEnumerated(int64(*v.ChargingUnit))
		retagged_enc_chargingunit, tagErr_enc_chargingunit := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_chargingunit)
		if tagErr_enc_chargingunit != nil {
			return nil, qualifyBERError(tagErr_enc_chargingunit, "chargingUnit", "encoding", false)
		}
		enc_chargingunit = retagged_enc_chargingunit
		children = append(children, enc_chargingunit...)
	}
	if v.Charge != nil {
		if !(int64(*v.Charge) >= 1 && int64(*v.Charge) <= 16777215) {
			if constraintErr := checkEncodedValue(opts, sd78d83_25, "37.3", "charge", "(1..16777215)", ber.ObserveInteger(int64(*v.Charge))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_charge := ber.EncodeInteger(int64(*v.Charge))
		retagged_enc_charge, tagErr_enc_charge := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_charge)
		if tagErr_enc_charge != nil {
			return nil, qualifyBERError(tagErr_enc_charge, "charge", "encoding", false)
		}
		enc_charge = retagged_enc_charge
		children = append(children, enc_charge...)
	}
	if v.SsChargingInfo != nil {
		if len((v.SsChargingInfo).Values) < 1 || len((v.SsChargingInfo).Values) > 30 {
			if constraintErr := checkEncodedLength(opts, sd78d83_25, "37.4", "ss-ChargingInfo", "SIZE (1..30)", len((v.SsChargingInfo).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscharginginfo, err := MarshalBERSSChargingInfo(v.SsChargingInfo, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "ss-ChargingInfo"))...)
		if err != nil {
			return nil, qualifyBERError(err, "ss-ChargingInfo", "encoding", false)
		}
		if ber.BERReplayEnabled(opts) && v.berSsChargingInfoIndef_ {
			// Strip the outer SEQUENCE tag from marshalBER output to get raw children.
			_, _, seqContent_, tlvErr_ := ber.DecodeEncodedTLV(enc_sscharginginfo)
			if tlvErr_ != nil {
				return nil, tlvErr_
			}
			{
				var encodeErr error
				enc_sscharginginfo, encodeErr = ber.EncodeConstructedIndefinite(tag.Tag{Class: tag.ClassContextSpecific, Number: 17}, seqContent_)
				if encodeErr != nil {
					return nil, qualifyBERError(encodeErr, "ss-ChargingInfo", "encoding", false)
				}
			}
		} else {
			retagged_enc_sscharginginfo, tagErr_enc_sscharginginfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_sscharginginfo)
			if tagErr_enc_sscharginginfo != nil {
				return nil, qualifyBERError(tagErr_enc_sscharginginfo, "ss-ChargingInfo", "encoding", false)
			}
			enc_sscharginginfo = retagged_enc_sscharginginfo
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_sscharginginfo)
		children = append(children, enc_sscharginginfo...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *RegisterChargingInformationArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes RegisterChargingInformationArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RegisterChargingInformationArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RegisterChargingInformationArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", true)
	}
	children = append(children, enc_msisdn...)
	if len(v.MscNumber) < 1 || len(v.MscNumber) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "mscNumber", "SIZE (1..10)", len(v.MscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MscNumber) < 1 || len(v.MscNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "mscNumber", "SIZE (1..20)", len(v.MscNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_mscnumber, encodeErr_enc_mscnumber := ber.EncodeOctetString([]byte(v.MscNumber))
	if encodeErr_enc_mscnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_mscnumber, "mscNumber", "encoding", true)
	}
	children = append(children, enc_mscnumber...)
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	if len(v.CallReference) < 1 || len(v.CallReference) > 3 {
		if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "callReference", "SIZE (1..3)", len(v.CallReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callreference, encodeErr_enc_callreference := ber.EncodeOctetString([]byte(v.CallReference))
	if encodeErr_enc_callreference != nil {
		return nil, qualifyBERError(encodeErr_enc_callreference, "callReference", "encoding", true)
	}
	children = append(children, enc_callreference...)
	if int64(v.CallType) != 0 && int64(v.CallType) != 1 && int64(v.CallType) != 2 && int64(v.CallType) != 3 && int64(v.CallType) != 4 {
		if constraintErr := checkEncodedValue(nil, sd78d83_25, "15", "callType", "ENUMERATED {0, 1, 2, 3, 4}", ber.ObserveInteger(int64(v.CallType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_calltype := ber.EncodeEnumerated(int64(v.CallType))
	children = append(children, enc_calltype...)
	if int64(v.CallStatus) != 0 && int64(v.CallStatus) != 1 && int64(v.CallStatus) != 2 && int64(v.CallStatus) != 4 && int64(v.CallStatus) != 5 && int64(v.CallStatus) != 6 && int64(v.CallStatus) != 7 && int64(v.CallStatus) != 8 && int64(v.CallStatus) != 9 && int64(v.CallStatus) != 10 && int64(v.CallStatus) != 11 && int64(v.CallStatus) != 12 && int64(v.CallStatus) != 13 {
		if constraintErr := checkEncodedValue(nil, sd78d83_25, "15", "callStatus", "ENUMERATED {0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}", ber.ObserveInteger(int64(v.CallStatus))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callstatus := ber.EncodeEnumerated(int64(v.CallStatus))
	children = append(children, enc_callstatus...)
	if len((v.CallDateTime).String()) < 14 || len((v.CallDateTime).String()) > 24 {
		if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "callDateTime", "SIZE (14..24)", len((v.CallDateTime).String())); constraintErr != nil {
			return nil, constraintErr
		}
	}
	{
		if timeErr := checkEncodedEditionTime(v.CallDateTime, sd78d83_25, "callDateTime"); timeErr != nil {
			return nil, timeErr
		}
		canonicalTimeSize, timeSizeErr := (v.CallDateTime).Canonical()
		if timeSizeErr != nil {
			return nil, timeSizeErr
		}
		if len((canonicalTimeSize).String()) < 14 || len((canonicalTimeSize).String()) > 24 {
			if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "callDateTime", "SIZE (14..24)", len((canonicalTimeSize).String())); constraintErr != nil {
				return nil, constraintErr
			}
		}
	}
	enc_calldatetime, encodeErr_enc_calldatetime := encodeEditionGeneralizedTimeDER(v.CallDateTime, sd78d83_25, "callDateTime")
	if encodeErr_enc_calldatetime != nil {
		if _, timeViolation := encodeErr_enc_calldatetime.(*ber.ValidationError); timeViolation {
			return nil, encodeErr_enc_calldatetime
		}

		return nil, qualifyBERError(encodeErr_enc_calldatetime, "callDateTime", "encoding", true)
	}
	children = append(children, enc_calldatetime...)
	if !(int64(v.CallDuration) >= 0 && int64(v.CallDuration) <= 16777215) {
		if constraintErr := checkEncodedValue(nil, sd78d83_25, "37.3", "callDuration", "(0..16777215)", ber.ObserveInteger(int64(v.CallDuration))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callduration := ber.EncodeInteger(int64(v.CallDuration))
	children = append(children, enc_callduration...)
	if v.BearerServiceCode != nil {
		if len(*v.BearerServiceCode) < 1 || len(*v.BearerServiceCode) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "bearerServiceCode", "SIZE (1)", len(*v.BearerServiceCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservicecode, encodeErr_enc_bearerservicecode := ber.EncodeOctetString([]byte(*v.BearerServiceCode))
		if encodeErr_enc_bearerservicecode != nil {
			return nil, qualifyBERError(encodeErr_enc_bearerservicecode, "bearerServiceCode", "encoding", true)
		}
		retagged_enc_bearerservicecode, tagErr_enc_bearerservicecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_bearerservicecode)
		if tagErr_enc_bearerservicecode != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservicecode, "bearerServiceCode", "encoding", true)
		}
		enc_bearerservicecode = retagged_enc_bearerservicecode
		children = append(children, enc_bearerservicecode...)
	}
	if v.TeleserviceCode != nil {
		if len(*v.TeleserviceCode) < 1 || len(*v.TeleserviceCode) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "teleserviceCode", "SIZE (1)", len(*v.TeleserviceCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicecode, encodeErr_enc_teleservicecode := ber.EncodeOctetString([]byte(*v.TeleserviceCode))
		if encodeErr_enc_teleservicecode != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservicecode, "teleserviceCode", "encoding", true)
		}
		retagged_enc_teleservicecode, tagErr_enc_teleservicecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 11, enc_teleservicecode)
		if tagErr_enc_teleservicecode != nil {
			return nil, qualifyBERError(tagErr_enc_teleservicecode, "teleserviceCode", "encoding", true)
		}
		enc_teleservicecode = retagged_enc_teleservicecode
		children = append(children, enc_teleservicecode...)
	}
	if v.CalledNumber != nil {
		if len(*v.CalledNumber) < 1 || len(*v.CalledNumber) > 10 {
			if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "calledNumber", "SIZE (1..10)", len(*v.CalledNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.CalledNumber) < 1 || len(*v.CalledNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "calledNumber", "SIZE (1..20)", len(*v.CalledNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callednumber, encodeErr_enc_callednumber := ber.EncodeOctetString([]byte(*v.CalledNumber))
		if encodeErr_enc_callednumber != nil {
			return nil, qualifyBERError(encodeErr_enc_callednumber, "calledNumber", "encoding", true)
		}
		retagged_enc_callednumber, tagErr_enc_callednumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 12, enc_callednumber)
		if tagErr_enc_callednumber != nil {
			return nil, qualifyBERError(tagErr_enc_callednumber, "calledNumber", "encoding", true)
		}
		enc_callednumber = retagged_enc_callednumber
		children = append(children, enc_callednumber...)
	}
	if v.CallingNumber != nil {
		if len(*v.CallingNumber) < 1 || len(*v.CallingNumber) > 10 {
			if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "callingNumber", "SIZE (1..10)", len(*v.CallingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.CallingNumber) < 1 || len(*v.CallingNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "callingNumber", "SIZE (1..20)", len(*v.CallingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callingnumber, encodeErr_enc_callingnumber := ber.EncodeOctetString([]byte(*v.CallingNumber))
		if encodeErr_enc_callingnumber != nil {
			return nil, qualifyBERError(encodeErr_enc_callingnumber, "callingNumber", "encoding", true)
		}
		retagged_enc_callingnumber, tagErr_enc_callingnumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 13, enc_callingnumber)
		if tagErr_enc_callingnumber != nil {
			return nil, qualifyBERError(tagErr_enc_callingnumber, "callingNumber", "encoding", true)
		}
		enc_callingnumber = retagged_enc_callingnumber
		children = append(children, enc_callingnumber...)
	}
	if v.PacketDataVolume != nil {
		if !(int64(*v.PacketDataVolume) >= 1 && int64(*v.PacketDataVolume) <= 100) {
			if constraintErr := checkEncodedValue(nil, sd78d83_25, "37.3", "packetDataVolume", "(1..100)", ber.ObserveInteger(int64(*v.PacketDataVolume))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_packetdatavolume := ber.EncodeInteger(int64(*v.PacketDataVolume))
		retagged_enc_packetdatavolume, tagErr_enc_packetdatavolume := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 14, enc_packetdatavolume)
		if tagErr_enc_packetdatavolume != nil {
			return nil, qualifyBERError(tagErr_enc_packetdatavolume, "packetDataVolume", "encoding", true)
		}
		enc_packetdatavolume = retagged_enc_packetdatavolume
		children = append(children, enc_packetdatavolume...)
	}
	if v.ChargingUnit != nil {
		if int64(*v.ChargingUnit) != 0 {
			if constraintErr := checkEncodedValue(nil, sd78d83_25, "15", "chargingUnit", "ENUMERATED {0}", ber.ObserveInteger(int64(*v.ChargingUnit))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_chargingunit := ber.EncodeEnumerated(int64(*v.ChargingUnit))
		retagged_enc_chargingunit, tagErr_enc_chargingunit := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 15, enc_chargingunit)
		if tagErr_enc_chargingunit != nil {
			return nil, qualifyBERError(tagErr_enc_chargingunit, "chargingUnit", "encoding", true)
		}
		enc_chargingunit = retagged_enc_chargingunit
		children = append(children, enc_chargingunit...)
	}
	if v.Charge != nil {
		if !(int64(*v.Charge) >= 1 && int64(*v.Charge) <= 16777215) {
			if constraintErr := checkEncodedValue(nil, sd78d83_25, "37.3", "charge", "(1..16777215)", ber.ObserveInteger(int64(*v.Charge))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_charge := ber.EncodeInteger(int64(*v.Charge))
		retagged_enc_charge, tagErr_enc_charge := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 16, enc_charge)
		if tagErr_enc_charge != nil {
			return nil, qualifyBERError(tagErr_enc_charge, "charge", "encoding", true)
		}
		enc_charge = retagged_enc_charge
		children = append(children, enc_charge...)
	}
	if v.SsChargingInfo != nil {
		if len((v.SsChargingInfo).Values) < 1 || len((v.SsChargingInfo).Values) > 30 {
			if constraintErr := checkEncodedLength(nil, sd78d83_25, "37.4", "ss-ChargingInfo", "SIZE (1..30)", len((v.SsChargingInfo).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_sscharginginfo, err := MarshalDERSSChargingInfo(v.SsChargingInfo)
		if err != nil {
			return nil, qualifyBERError(err, "ss-ChargingInfo", "encoding", true)
		}
		retagged_enc_sscharginginfo, tagErr_enc_sscharginginfo := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 17, enc_sscharginginfo)
		if tagErr_enc_sscharginginfo != nil {
			return nil, qualifyBERError(tagErr_enc_sscharginginfo, "ss-ChargingInfo", "encoding", true)
		}
		enc_sscharginginfo = retagged_enc_sscharginginfo
		children = append(children, enc_sscharginginfo...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RegisterChargingInformationArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *RegisterChargingInformationArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RegisterChargingInformationArgument from BER/DER format.
func (destination *RegisterChargingInformationArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RegisterChargingInformationArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(RegisterChargingInformationArgument)

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
			var probe RegisterChargingInformationArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_25, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RegisterChargingInformationArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RegisterChargingInformationArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding RegisterChargingInformationArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterChargingInformationArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msIsdn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field msIsdn", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "msIsdn", content[offset:])
		val_msisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msIsdn", "decoding", false)
		}
		v.MsIsdn = IsdnAddressString(val_msisdn)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode mscNumber
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field mscNumber", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "mscNumber", content[offset:])
		val_mscnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "mscNumber", "decoding", false)
		}
		v.MscNumber = IsdnAddressString(val_mscnumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.MscNumber) < 1 || len(v.MscNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "mscNumber", "SIZE (1..10)", len(v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.MscNumber) < 1 || len(v.MscNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "mscNumber", "SIZE (1..20)", len(v.MscNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
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
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode callReference
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field callReference", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "callReference", content[offset:])
		val_callreference, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "callReference", "decoding", false)
		}
		v.CallReference = CallReference(val_callreference)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.CallReference) < 1 || len(v.CallReference) > 3 {
			if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "callReference", "SIZE (1..3)", len(v.CallReference)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode callType
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field callType", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "callType", content[offset:])
		val_calltype, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "callType", "decoding", false)
		}
		v.CallType = CallType(val_calltype)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.CallType) != 0 && int64(v.CallType) != 1 && int64(v.CallType) != 2 && int64(v.CallType) != 3 && int64(v.CallType) != 4 {
			if constraintErr := checkDecodedValue(opts, sd78d83_25, "15", "callType", "ENUMERATED {0, 1, 2, 3, 4}", ber.ObserveInteger(int64(v.CallType))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode callStatus
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field callStatus", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "callStatus", content[offset:])
		val_callstatus, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "callStatus", "decoding", false)
		}
		v.CallStatus = CallStatus(val_callstatus)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.CallStatus) != 0 && int64(v.CallStatus) != 1 && int64(v.CallStatus) != 2 && int64(v.CallStatus) != 4 && int64(v.CallStatus) != 5 && int64(v.CallStatus) != 6 && int64(v.CallStatus) != 7 && int64(v.CallStatus) != 8 && int64(v.CallStatus) != 9 && int64(v.CallStatus) != 10 && int64(v.CallStatus) != 11 && int64(v.CallStatus) != 12 && int64(v.CallStatus) != 13 {
			if constraintErr := checkDecodedValue(opts, sd78d83_25, "15", "callStatus", "ENUMERATED {0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}", ber.ObserveInteger(int64(v.CallStatus))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode callDateTime
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field callDateTime", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "callDateTime", content[offset:])
		val_calldatetime, n, err := decodeEditionGeneralizedTime(content[offset:], sd78d83_25, "callDateTime", opts...)
		if err != nil {
			if _, timeViolation := err.(*ber.ValidationError); timeViolation {
				return err
			}

			return qualifyBERError(err, "callDateTime", "decoding", false)
		}
		v.CallDateTime = val_calldatetime
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len((v.CallDateTime).String()) < 14 || len((v.CallDateTime).String()) > 24 {
			if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "callDateTime", "SIZE (14..24)", len((v.CallDateTime).String())); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode callDuration
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field callDuration", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "callDuration", content[offset:])
		val_callduration, n, err := ber.DecodeInteger(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "callDuration", "decoding", false)
		}
		v.CallDuration = CallDuration(val_callduration)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if !(int64(v.CallDuration) >= 0 && int64(v.CallDuration) <= 16777215) {
			if constraintErr := checkDecodedValue(opts, sd78d83_25, "37.3", "callDuration", "(0..16777215)", ber.ObserveInteger(int64(v.CallDuration))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode bearerServiceCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "bearerServiceCode", content[offset:])
				decodedTag_bearerservicecode, n_bearerservicecode, rawVal_bearerservicecode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bearerServiceCode", "decoding", false)
				}
				if decodedTag_bearerservicecode.Class != tag.ClassContextSpecific || decodedTag_bearerservicecode.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_bearerservicecode), "bearerServiceCode", "decoding", false)
				}
				decVal_bearerservicecode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_bearerservicecode.Constructed, rawVal_bearerservicecode, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "bearerServiceCode", "decoding", false)
				}
				tmp_bearerservicecode := BearerServiceCode(decVal_bearerservicecode)
				v.BearerServiceCode = &tmp_bearerservicecode
				if offset < 0 || offset >
					len(content) || n_bearerservicecode < 0 || n_bearerservicecode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bearerservicecode
				if len(*v.BearerServiceCode) < 1 || len(*v.BearerServiceCode) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "bearerServiceCode", "SIZE (1)", len(*v.BearerServiceCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode teleserviceCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 11 {
				ber.MarkPreflightTarget(opts, "teleserviceCode", content[offset:])
				decodedTag_teleservicecode, n_teleservicecode, rawVal_teleservicecode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "teleserviceCode", "decoding", false)
				}
				if decodedTag_teleservicecode.Class != tag.ClassContextSpecific || decodedTag_teleservicecode.Number != 11 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_teleservicecode), "teleserviceCode", "decoding", false)
				}
				decVal_teleservicecode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_teleservicecode.Constructed, rawVal_teleservicecode, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "teleserviceCode", "decoding", false)
				}
				tmp_teleservicecode := TeleserviceCode(decVal_teleservicecode)
				v.TeleserviceCode = &tmp_teleservicecode
				if offset < 0 || offset >
					len(content) || n_teleservicecode < 0 || n_teleservicecode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_teleservicecode
				if len(*v.TeleserviceCode) < 1 || len(*v.TeleserviceCode) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "teleserviceCode", "SIZE (1)", len(*v.TeleserviceCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode calledNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 12 {
				ber.MarkPreflightTarget(opts, "calledNumber", content[offset:])
				decodedTag_callednumber, n_callednumber, rawVal_callednumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "calledNumber", "decoding", false)
				}
				if decodedTag_callednumber.Class != tag.ClassContextSpecific || decodedTag_callednumber.Number != 12 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_callednumber), "calledNumber", "decoding", false)
				}
				decVal_callednumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_callednumber.Constructed, rawVal_callednumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "calledNumber", "decoding", false)
				}
				tmp_callednumber := IsdnAddressString(decVal_callednumber)
				v.CalledNumber = &tmp_callednumber
				if offset < 0 || offset >
					len(content) || n_callednumber < 0 || n_callednumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callednumber
				if len(*v.CalledNumber) < 1 || len(*v.CalledNumber) > 10 {
					if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "calledNumber", "SIZE (1..10)", len(*v.CalledNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.CalledNumber) < 1 || len(*v.CalledNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "calledNumber", "SIZE (1..20)", len(*v.CalledNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode callingNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 13 {
				ber.MarkPreflightTarget(opts, "callingNumber", content[offset:])
				decodedTag_callingnumber, n_callingnumber, rawVal_callingnumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callingNumber", "decoding", false)
				}
				if decodedTag_callingnumber.Class != tag.ClassContextSpecific || decodedTag_callingnumber.Number != 13 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_callingnumber), "callingNumber", "decoding", false)
				}
				decVal_callingnumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_callingnumber.Constructed, rawVal_callingnumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "callingNumber", "decoding", false)
				}
				tmp_callingnumber := IsdnAddressString(decVal_callingnumber)
				v.CallingNumber = &tmp_callingnumber
				if offset < 0 || offset >
					len(content) || n_callingnumber < 0 || n_callingnumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callingnumber
				if len(*v.CallingNumber) < 1 || len(*v.CallingNumber) > 10 {
					if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "callingNumber", "SIZE (1..10)", len(*v.CallingNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.CallingNumber) < 1 || len(*v.CallingNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "callingNumber", "SIZE (1..20)", len(*v.CallingNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode packetDataVolume
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 14 {
				ber.MarkPreflightTarget(opts, "packetDataVolume", content[offset:])
				decodedTag_packetdatavolume, n_packetdatavolume, rawVal_packetdatavolume, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "packetDataVolume", "decoding", false)
				}
				if decodedTag_packetdatavolume.Class != tag.ClassContextSpecific || decodedTag_packetdatavolume.Number != 14 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_packetdatavolume), "packetDataVolume", "decoding", false)
				}
				if decodedTag_packetdatavolume.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_packetdatavolume), "packetDataVolume", "decoding", false)
				}
				decVal_packetdatavolume, intErr := ber.DecodeIntegerValue(rawVal_packetdatavolume)
				if intErr != nil {
					return qualifyBERError(intErr, "packetDataVolume", "decoding", false)
				}
				tmp_packetdatavolume := PacketDataVolume(decVal_packetdatavolume)
				v.PacketDataVolume = &tmp_packetdatavolume
				if offset < 0 || offset >
					len(content) || n_packetdatavolume < 0 || n_packetdatavolume > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_packetdatavolume
				if !(int64(*v.PacketDataVolume) >= 1 && int64(*v.PacketDataVolume) <= 100) {
					if constraintErr := checkDecodedValue(opts, sd78d83_25, "37.3", "packetDataVolume", "(1..100)", ber.ObserveInteger(int64(*v.PacketDataVolume))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode chargingUnit
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 15 {
				ber.MarkPreflightTarget(opts, "chargingUnit", content[offset:])
				decodedTag_chargingunit, n_chargingunit, rawVal_chargingunit, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "chargingUnit", "decoding", false)
				}
				if decodedTag_chargingunit.Class != tag.ClassContextSpecific || decodedTag_chargingunit.Number != 15 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_chargingunit), "chargingUnit", "decoding", false)
				}
				if decodedTag_chargingunit.Constructed != false {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_chargingunit), "chargingUnit", "decoding", false)
				}
				decVal_chargingunit, intErr := ber.DecodeEnumeratedValue(rawVal_chargingunit)
				if intErr != nil {
					return qualifyBERError(intErr, "chargingUnit", "decoding", false)
				}
				tmp_chargingunit := ChargingUnit(decVal_chargingunit)
				v.ChargingUnit = &tmp_chargingunit
				if offset < 0 || offset >
					len(content) || n_chargingunit < 0 || n_chargingunit > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_chargingunit
				if int64(*v.ChargingUnit) != 0 {
					if constraintErr := checkDecodedValue(opts, sd78d83_25, "15", "chargingUnit", "ENUMERATED {0}", ber.ObserveInteger(int64(*v.ChargingUnit))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode charge
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "charge", content[offset:])
				decodedTag_charge, n_charge, rawVal_charge, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "charge", "decoding", false)
				}
				if decodedTag_charge.Class != tag.ClassContextSpecific || decodedTag_charge.Number != 16 {
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
					if constraintErr := checkDecodedValue(opts, sd78d83_25, "37.3", "charge", "(1..16777215)", ber.ObserveInteger(int64(*v.Charge))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode ss-ChargingInfo
	v.berSsChargingInfoIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 17 {
				ber.MarkPreflightTarget(opts, "ss-ChargingInfo", content[offset:])
				decodedTag_sscharginginfo, n_sscharginginfo, rawVal_sscharginginfo, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "ss-ChargingInfo", "decoding", false)
				}
				if decodedTag_sscharginginfo.Class != tag.ClassContextSpecific || decodedTag_sscharginginfo.Number != 17 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_sscharginginfo), "ss-ChargingInfo", "decoding", false)
				}
				if decodedTag_sscharginginfo.Constructed != true {
					return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_sscharginginfo), "ss-ChargingInfo", "decoding", false)
				}
				_ = rawVal_sscharginginfo
				if offset < 0 || offset >
					len(content) || n_sscharginginfo < 0 || n_sscharginginfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				reconstructed_sscharginginfo, reconstructionErr_sscharginginfo := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, content[offset:offset+n_sscharginginfo])
				if reconstructionErr_sscharginginfo != nil {
					return qualifyBERError(reconstructionErr_sscharginginfo, "ss-ChargingInfo", "decoding", false)
				}
				dec_sscharginginfo, unmErr := UnmarshalBERSSChargingInfo(reconstructed_sscharginginfo, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "ss-ChargingInfo"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "ss-ChargingInfo", "decoding", false)
				}
				v.SsChargingInfo = dec_sscharginginfo
				{
					_, tagSz_, _ := ber.DecodeTag(content[offset:])
					if offset < 0 || offset >
						len(content) || tagSz_ < 0 || tagSz_ > len(content[offset:]) {
						return fmt.Errorf("invalid BER content window")
					}

					if offset+tagSz_ < len(content) && content[offset+tagSz_] == 0x80 {
						v.berSsChargingInfoIndef_ = true
					}
				}
				if offset < 0 || offset >
					len(content) || n_sscharginginfo < 0 || n_sscharginginfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_sscharginginfo
				if len((v.SsChargingInfo).Values) < 1 || len((v.SsChargingInfo).Values) > 30 {
					if constraintErr := checkDecodedLength(opts, sd78d83_25, "37.4", "ss-ChargingInfo", "SIZE (1..30)", len((v.SsChargingInfo).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "RegisterChargingInformationArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes RegisterSSArgument to BER format.
func (v *RegisterSSArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: RegisterSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*RegisterSSArgument).MarshalBER, (*RegisterSSArgument).marshalBER, 3)

}
func (v *RegisterSSArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(opts, sd78d83_26, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_26, "37.4", "forwardedToNumber", "SIZE (1..10)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_26, "37.4", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := checkEncodedValue(opts, sd78d83_26, "37.3", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *RegisterSSArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes RegisterSSArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *RegisterSSArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: RegisterSSArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.SsCode) < 1 || len(v.SsCode) > 1 {
		if constraintErr := checkEncodedLength(nil, sd78d83_26, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 10 {
			if constraintErr := checkEncodedLength(nil, sd78d83_26, "37.4", "forwardedToNumber", "SIZE (1..10)", len(*v.ForwardedToNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_26, "37.4", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
	if v.NoReplyConditionTime != nil {
		if !(int64(*v.NoReplyConditionTime) >= 5 && int64(*v.NoReplyConditionTime) <= 30) {
			if constraintErr := checkEncodedValue(nil, sd78d83_26, "37.3", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding RegisterSSArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *RegisterSSArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes RegisterSSArgument from BER/DER format.
func (destination *RegisterSSArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: RegisterSSArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(RegisterSSArgument)

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
			var probe RegisterSSArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_26, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = RegisterSSArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*RegisterSSArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding RegisterSSArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "RegisterSSArgument", Cause: ber.ErrExtraData}
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
			if constraintErr := checkDecodedLength(opts, sd78d83_26, "37.4", "ss-Code", "SIZE (1)", len(v.SsCode)); constraintErr != nil {
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
					len(content) || n_basicservice < 0 || n_basicservice > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				if unmErr := dec_basicservice.UnmarshalBER(content[offset:offset+n_basicservice], ber.ChildDecodeOptions(opts, "basicService")...); unmErr != nil {
					return qualifyBERError(unmErr, "basicService", "decoding", false)
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
				tmp_forwardedtonumber := IsdnAddressString(decVal_forwardedtonumber)
				v.ForwardedToNumber = &tmp_forwardedtonumber
				if offset < 0 || offset >
					len(content) || n_forwardedtonumber < 0 || n_forwardedtonumber >
					len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_forwardedtonumber
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 10 {
					if constraintErr := checkDecodedLength(opts, sd78d83_26, "37.4", "forwardedToNumber", "SIZE (1..10)", len(*v.ForwardedToNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.ForwardedToNumber) < 1 || len(*v.ForwardedToNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_26, "37.4", "forwardedToNumber", "SIZE (1..20)", len(*v.ForwardedToNumber)); constraintErr != nil {
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
					if constraintErr := checkDecodedValue(opts, sd78d83_26, "37.3", "noReplyConditionTime", "(5..30)", ber.ObserveInteger(int64(*v.NoReplyConditionTime))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "RegisterSSArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes ResetArgument to BER format.
func (v *ResetArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: ResetArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*ResetArgument).MarshalBER, (*ResetArgument).marshalBER, 3)

}
func (v *ResetArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.NetworkResource) != 0 && int64(v.NetworkResource) != 1 && int64(v.NetworkResource) != 2 && int64(v.NetworkResource) != 3 && int64(v.NetworkResource) != 4 && int64(v.NetworkResource) != 5 && int64(v.NetworkResource) != 6 && int64(v.NetworkResource) != 7 {
		if constraintErr := checkEncodedValue(opts, sd78d83_27, "15", "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", ber.ObserveInteger(int64(v.NetworkResource))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_networkresource := ber.EncodeEnumerated(int64(v.NetworkResource))
	children = append(children, enc_networkresource...)
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_27, "37.4", "originatingEntityNumber", "SIZE (1..10)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_27, "37.4", "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_originatingentitynumber, encodeErr_enc_originatingentitynumber := ber.EncodeOctetString([]byte(v.OriginatingEntityNumber))
	if encodeErr_enc_originatingentitynumber != nil {
		return nil, qualifyBERError(encodeErr_enc_originatingentitynumber, "originatingEntityNumber", "encoding", false)
	}
	children = append(children, enc_originatingentitynumber...)
	if v.HlrId != nil {
		if len((v.HlrId).Values) < 1 || len((v.HlrId).Values) > 50 {
			if constraintErr := checkEncodedLength(opts, sd78d83_27, "37.4", "hlrId", "SIZE (1..50)", len((v.HlrId).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hlrid, err := MarshalBERHlrList(v.HlrId, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "hlrId"))...)
		if err != nil {
			return nil, qualifyBERError(err, "hlrId", "encoding", false)
		}
		ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_hlrid)
		children = append(children, enc_hlrid...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *ResetArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes ResetArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *ResetArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: ResetArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.NetworkResource) != 0 && int64(v.NetworkResource) != 1 && int64(v.NetworkResource) != 2 && int64(v.NetworkResource) != 3 && int64(v.NetworkResource) != 4 && int64(v.NetworkResource) != 5 && int64(v.NetworkResource) != 6 && int64(v.NetworkResource) != 7 {
		if constraintErr := checkEncodedValue(nil, sd78d83_27, "15", "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", ber.ObserveInteger(int64(v.NetworkResource))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_networkresource := ber.EncodeEnumerated(int64(v.NetworkResource))
	children = append(children, enc_networkresource...)
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_27, "37.4", "originatingEntityNumber", "SIZE (1..10)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_27, "37.4", "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_originatingentitynumber, encodeErr_enc_originatingentitynumber := ber.EncodeOctetString([]byte(v.OriginatingEntityNumber))
	if encodeErr_enc_originatingentitynumber != nil {
		return nil, qualifyBERError(encodeErr_enc_originatingentitynumber, "originatingEntityNumber", "encoding", true)
	}
	children = append(children, enc_originatingentitynumber...)
	if v.HlrId != nil {
		if len((v.HlrId).Values) < 1 || len((v.HlrId).Values) > 50 {
			if constraintErr := checkEncodedLength(nil, sd78d83_27, "37.4", "hlrId", "SIZE (1..50)", len((v.HlrId).Values)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_hlrid, err := MarshalDERHlrList(v.HlrId)
		if err != nil {
			return nil, qualifyBERError(err, "hlrId", "encoding", true)
		}
		children = append(children, enc_hlrid...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding ResetArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *ResetArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes ResetArgument from BER/DER format.
func (destination *ResetArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: ResetArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(ResetArgument)

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
			var probe ResetArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_27, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = ResetArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*ResetArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding ResetArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "ResetArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode networkResource
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field networkResource", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "networkResource", content[offset:])
		val_networkresource, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "networkResource", "decoding", false)
		}
		v.NetworkResource = NetworkResource(val_networkresource)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.NetworkResource) != 0 && int64(v.NetworkResource) != 1 && int64(v.NetworkResource) != 2 && int64(v.NetworkResource) != 3 && int64(v.NetworkResource) != 4 && int64(v.NetworkResource) != 5 && int64(v.NetworkResource) != 6 && int64(v.NetworkResource) != 7 {
			if constraintErr := checkDecodedValue(opts, sd78d83_27, "15", "networkResource", "ENUMERATED {0, 1, 2, 3, 4, 5, 6, 7}", ber.ObserveInteger(int64(v.NetworkResource))); constraintErr != nil {
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
		v.OriginatingEntityNumber = IsdnAddressString(val_originatingentitynumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_27, "37.4", "originatingEntityNumber", "SIZE (1..10)", len(v.OriginatingEntityNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.OriginatingEntityNumber) < 1 || len(v.OriginatingEntityNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_27, "37.4", "originatingEntityNumber", "SIZE (1..20)", len(v.OriginatingEntityNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode hlrId
	v.berHlrIdIndef_ = false
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 {
				ber.MarkPreflightTarget(opts, "hlrId", content[offset:])
				// Decode nested SEQUENCE_OF (HlrList)
				_, n_hlrid, _, tlvErr_hlrid := ber.DecodeTLV(content[offset:], opts...)
				if tlvErr_hlrid != nil {
					return qualifyBERError(tlvErr_hlrid, "hlrId", "decoding", false)
				}
				if offset < 0 || offset >
					len(content) || n_hlrid < 0 || n_hlrid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				tlv_hlrid := content[offset : offset+n_hlrid]
				{
					_, tagSz_, _ := ber.DecodeTag(tlv_hlrid)
					if tagSz_ < len(tlv_hlrid) && tlv_hlrid[tagSz_] == 0x80 {
						v.berHlrIdIndef_ = true
					}
				}
				dec_hlrid, unmErr := UnmarshalBERHlrList(tlv_hlrid, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "hlrId"))...)
				if unmErr != nil {
					return qualifyBERError(unmErr, "hlrId", "decoding", false)
				}
				v.HlrId = dec_hlrid
				if offset < 0 || offset >
					len(content) || n_hlrid < 0 || n_hlrid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_hlrid
				if len((v.HlrId).Values) < 1 || len((v.HlrId).Values) > 50 {
					if constraintErr := checkDecodedLength(opts, sd78d83_27, "37.4", "hlrId", "SIZE (1..50)", len((v.HlrId).Values)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "ResetArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SearchForMobileSubscriberArgument to BER format.
func (v *SearchForMobileSubscriberArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SearchForMobileSubscriberArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SearchForMobileSubscriberArgument).MarshalBER, (*SearchForMobileSubscriberArgument).marshalBER, 3)

}
func (v *SearchForMobileSubscriberArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, sd78d83_28, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	enc_storedlocationarea, err := v.StoredLocationArea.MarshalBER(ber.ChildEncodeOptions(opts, "storedLocationArea")...)
	if err != nil {
		return nil, qualifyBERError(err, "storedLocationArea", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_storedlocationarea)
	children = append(children, enc_storedlocationarea...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SearchForMobileSubscriberArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SearchForMobileSubscriberArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SearchForMobileSubscriberArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SearchForMobileSubscriberArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, sd78d83_28, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	enc_storedlocationarea, err := v.StoredLocationArea.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "storedLocationArea", "encoding", true)
	}
	children = append(children, enc_storedlocationarea...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SearchForMobileSubscriberArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SearchForMobileSubscriberArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SearchForMobileSubscriberArgument from BER/DER format.
func (destination *SearchForMobileSubscriberArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SearchForMobileSubscriberArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(SearchForMobileSubscriberArgument)

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
			var probe SearchForMobileSubscriberArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_28, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SearchForMobileSubscriberArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SearchForMobileSubscriberArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SearchForMobileSubscriberArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SearchForMobileSubscriberArgument", Cause: ber.ErrExtraData}
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
		if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, sd78d83_28, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode storedLocationArea
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field storedLocationArea", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "storedLocationArea", content[offset:])
		// Decode nested CHOICE (SearchForMobileSubscriberArgumentStoredLocationArea)
		_, n_storedlocationarea, _, tlvErr_storedlocationarea := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_storedlocationarea != nil {
			return qualifyBERError(tlvErr_storedlocationarea, "storedLocationArea", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_storedlocationarea < 0 || n_storedlocationarea > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.StoredLocationArea.UnmarshalBER(content[offset:offset+n_storedlocationarea], ber.ChildDecodeOptions(opts, "storedLocationArea")...); unmErr != nil {
			return qualifyBERError(unmErr, "storedLocationArea", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_storedlocationarea < 0 || n_storedlocationarea > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_storedlocationarea
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SearchForMobileSubscriberArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SendInfoForIncomingCallArgument to BER format.
func (v *SendInfoForIncomingCallArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendInfoForIncomingCallArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendInfoForIncomingCallArgument).MarshalBER, (*SendInfoForIncomingCallArgument).marshalBER, 3)

}
func (v *SendInfoForIncomingCallArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_incomingid, err := v.IncomingId.MarshalBER(ber.ChildEncodeOptions(opts, "incomingId")...)
	if err != nil {
		return nil, qualifyBERError(err, "incomingId", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_incomingid)
	children = append(children, enc_incomingid...)
	if v.BearerService != nil {
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_29, "37.4", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservice, encodeErr_enc_bearerservice := ber.EncodeOctetString([]byte(*v.BearerService))
		if encodeErr_enc_bearerservice != nil {
			return nil, qualifyBERError(encodeErr_enc_bearerservice, "bearerService", "encoding", false)
		}
		retagged_enc_bearerservice, tagErr_enc_bearerservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_bearerservice)
		if tagErr_enc_bearerservice != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservice, "bearerService", "encoding", false)
		}
		enc_bearerservice = retagged_enc_bearerservice
		children = append(children, enc_bearerservice...)
	}
	if v.Teleservice != nil {
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_29, "37.4", "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(*v.Teleservice))
		if encodeErr_enc_teleservice != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservice, "teleservice", "encoding", false)
		}
		retagged_enc_teleservice, tagErr_enc_teleservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_teleservice)
		if tagErr_enc_teleservice != nil {
			return nil, qualifyBERError(tagErr_enc_teleservice, "teleservice", "encoding", false)
		}
		enc_teleservice = retagged_enc_teleservice
		children = append(children, enc_teleservice...)
	}
	if v.LMsId != nil {
		if len(*v.LMsId) < 4 || len(*v.LMsId) > 4 {
			if constraintErr := checkEncodedLength(opts, sd78d83_29, "37.4", "lMsId", "SIZE (4)", len(*v.LMsId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsid, encodeErr_enc_lmsid := ber.EncodeOctetString([]byte(*v.LMsId))
		if encodeErr_enc_lmsid != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsid, "lMsId", "encoding", false)
		}
		retagged_enc_lmsid, tagErr_enc_lmsid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lmsid)
		if tagErr_enc_lmsid != nil {
			return nil, qualifyBERError(tagErr_enc_lmsid, "lMsId", "encoding", false)
		}
		enc_lmsid = retagged_enc_lmsid
		children = append(children, enc_lmsid...)
	}
	if v.DialledNumber != nil {
		if len(*v.DialledNumber) < 1 || len(*v.DialledNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_29, "37.4", "dialledNumber", "SIZE (1..10)", len(*v.DialledNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.DialledNumber) < 1 || len(*v.DialledNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_29, "37.4", "dialledNumber", "SIZE (1..20)", len(*v.DialledNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_diallednumber, encodeErr_enc_diallednumber := ber.EncodeOctetString([]byte(*v.DialledNumber))
		if encodeErr_enc_diallednumber != nil {
			return nil, qualifyBERError(encodeErr_enc_diallednumber, "dialledNumber", "encoding", false)
		}
		retagged_enc_diallednumber, tagErr_enc_diallednumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_diallednumber)
		if tagErr_enc_diallednumber != nil {
			return nil, qualifyBERError(tagErr_enc_diallednumber, "dialledNumber", "encoding", false)
		}
		enc_diallednumber = retagged_enc_diallednumber
		children = append(children, enc_diallednumber...)
	}
	if v.CugInterlock != nil {
		if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
			if constraintErr := checkEncodedLength(opts, sd78d83_29, "37.4", "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
		if encodeErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", false)
		}
		retagged_enc_cuginterlock, tagErr_enc_cuginterlock := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_cuginterlock)
		if tagErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(tagErr_enc_cuginterlock, "cug-Interlock", "encoding", false)
		}
		enc_cuginterlock = retagged_enc_cuginterlock
		children = append(children, enc_cuginterlock...)
	}
	if v.NumberOfForwarding != nil {
		if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
			if constraintErr := checkEncodedValue(opts, sd78d83_29, "37.3", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		retagged_enc_numberofforwarding, tagErr_enc_numberofforwarding := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_numberofforwarding)
		if tagErr_enc_numberofforwarding != nil {
			return nil, qualifyBERError(tagErr_enc_numberofforwarding, "numberOfForwarding", "encoding", false)
		}
		enc_numberofforwarding = retagged_enc_numberofforwarding
		children = append(children, enc_numberofforwarding...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendInfoForIncomingCallArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendInfoForIncomingCallArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendInfoForIncomingCallArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendInfoForIncomingCallArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_incomingid, err := v.IncomingId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "incomingId", "encoding", true)
	}
	children = append(children, enc_incomingid...)
	if v.BearerService != nil {
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_29, "37.4", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservice, encodeErr_enc_bearerservice := ber.EncodeOctetString([]byte(*v.BearerService))
		if encodeErr_enc_bearerservice != nil {
			return nil, qualifyBERError(encodeErr_enc_bearerservice, "bearerService", "encoding", true)
		}
		retagged_enc_bearerservice, tagErr_enc_bearerservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_bearerservice)
		if tagErr_enc_bearerservice != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservice, "bearerService", "encoding", true)
		}
		enc_bearerservice = retagged_enc_bearerservice
		children = append(children, enc_bearerservice...)
	}
	if v.Teleservice != nil {
		if len(*v.Teleservice) < 1 || len(*v.Teleservice) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_29, "37.4", "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(*v.Teleservice))
		if encodeErr_enc_teleservice != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservice, "teleservice", "encoding", true)
		}
		retagged_enc_teleservice, tagErr_enc_teleservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_teleservice)
		if tagErr_enc_teleservice != nil {
			return nil, qualifyBERError(tagErr_enc_teleservice, "teleservice", "encoding", true)
		}
		enc_teleservice = retagged_enc_teleservice
		children = append(children, enc_teleservice...)
	}
	if v.LMsId != nil {
		if len(*v.LMsId) < 4 || len(*v.LMsId) > 4 {
			if constraintErr := checkEncodedLength(nil, sd78d83_29, "37.4", "lMsId", "SIZE (4)", len(*v.LMsId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsid, encodeErr_enc_lmsid := ber.EncodeOctetString([]byte(*v.LMsId))
		if encodeErr_enc_lmsid != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsid, "lMsId", "encoding", true)
		}
		retagged_enc_lmsid, tagErr_enc_lmsid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_lmsid)
		if tagErr_enc_lmsid != nil {
			return nil, qualifyBERError(tagErr_enc_lmsid, "lMsId", "encoding", true)
		}
		enc_lmsid = retagged_enc_lmsid
		children = append(children, enc_lmsid...)
	}
	if v.DialledNumber != nil {
		if len(*v.DialledNumber) < 1 || len(*v.DialledNumber) > 10 {
			if constraintErr := checkEncodedLength(nil, sd78d83_29, "37.4", "dialledNumber", "SIZE (1..10)", len(*v.DialledNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.DialledNumber) < 1 || len(*v.DialledNumber) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_29, "37.4", "dialledNumber", "SIZE (1..20)", len(*v.DialledNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_diallednumber, encodeErr_enc_diallednumber := ber.EncodeOctetString([]byte(*v.DialledNumber))
		if encodeErr_enc_diallednumber != nil {
			return nil, qualifyBERError(encodeErr_enc_diallednumber, "dialledNumber", "encoding", true)
		}
		retagged_enc_diallednumber, tagErr_enc_diallednumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_diallednumber)
		if tagErr_enc_diallednumber != nil {
			return nil, qualifyBERError(tagErr_enc_diallednumber, "dialledNumber", "encoding", true)
		}
		enc_diallednumber = retagged_enc_diallednumber
		children = append(children, enc_diallednumber...)
	}
	if v.CugInterlock != nil {
		if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
			if constraintErr := checkEncodedLength(nil, sd78d83_29, "37.4", "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
		if encodeErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", true)
		}
		retagged_enc_cuginterlock, tagErr_enc_cuginterlock := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 6, enc_cuginterlock)
		if tagErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(tagErr_enc_cuginterlock, "cug-Interlock", "encoding", true)
		}
		enc_cuginterlock = retagged_enc_cuginterlock
		children = append(children, enc_cuginterlock...)
	}
	if v.NumberOfForwarding != nil {
		if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
			if constraintErr := checkEncodedValue(nil, sd78d83_29, "37.3", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_numberofforwarding := ber.EncodeInteger(int64(*v.NumberOfForwarding))
		retagged_enc_numberofforwarding, tagErr_enc_numberofforwarding := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 7, enc_numberofforwarding)
		if tagErr_enc_numberofforwarding != nil {
			return nil, qualifyBERError(tagErr_enc_numberofforwarding, "numberOfForwarding", "encoding", true)
		}
		enc_numberofforwarding = retagged_enc_numberofforwarding
		children = append(children, enc_numberofforwarding...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendInfoForIncomingCallArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendInfoForIncomingCallArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendInfoForIncomingCallArgument from BER/DER format.
func (destination *SendInfoForIncomingCallArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendInfoForIncomingCallArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendInfoForIncomingCallArgument)

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
			var probe SendInfoForIncomingCallArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_29, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendInfoForIncomingCallArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendInfoForIncomingCallArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendInfoForIncomingCallArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendInfoForIncomingCallArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode incomingId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field incomingId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "incomingId", content[offset:])
		// Decode nested CHOICE (SendInfoForIncomingCallArgumentIncomingId)
		_, n_incomingid, _, tlvErr_incomingid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_incomingid != nil {
			return qualifyBERError(tlvErr_incomingid, "incomingId", "decoding", false)
		}
		if offset > len(content) || n_incomingid < 0 || n_incomingid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.IncomingId.UnmarshalBER(content[offset:offset+n_incomingid], ber.ChildDecodeOptions(opts, "incomingId")...); unmErr != nil {
			return qualifyBERError(unmErr, "incomingId", "decoding", false)
		}
		if offset > len(content) || n_incomingid < 0 || n_incomingid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_incomingid
	}
	// Decode bearerService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "bearerService", content[offset:])
				decodedTag_bearerservice, n_bearerservice, rawVal_bearerservice, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bearerService", "decoding", false)
				}
				if decodedTag_bearerservice.Class != tag.ClassContextSpecific || decodedTag_bearerservice.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_bearerservice), "bearerService", "decoding", false)
				}
				decVal_bearerservice, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_bearerservice.Constructed, rawVal_bearerservice, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "bearerService", "decoding", false)
				}
				tmp_bearerservice := BearerServiceCode(decVal_bearerservice)
				v.BearerService = &tmp_bearerservice
				if offset < 0 || offset >
					len(content) || n_bearerservice < 0 || n_bearerservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bearerservice
				if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_29, "37.4", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode teleservice
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "teleservice", content[offset:])
				decodedTag_teleservice, n_teleservice, rawVal_teleservice, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "teleservice", "decoding", false)
				}
				if decodedTag_teleservice.Class != tag.ClassContextSpecific || decodedTag_teleservice.Number != 3 {
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
					if constraintErr := checkDecodedLength(opts, sd78d83_29, "37.4", "teleservice", "SIZE (1)", len(*v.Teleservice)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode lMsId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "lMsId", content[offset:])
				decodedTag_lmsid, n_lmsid, rawVal_lmsid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lMsId", "decoding", false)
				}
				if decodedTag_lmsid.Class != tag.ClassContextSpecific || decodedTag_lmsid.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_lmsid), "lMsId", "decoding", false)
				}
				decVal_lmsid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lmsid.Constructed, rawVal_lmsid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lMsId", "decoding", false)
				}
				tmp_lmsid := LMsId(decVal_lmsid)
				v.LMsId = &tmp_lmsid
				if offset < 0 || offset >
					len(content) || n_lmsid < 0 || n_lmsid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lmsid
				if len(*v.LMsId) < 4 || len(*v.LMsId) > 4 {
					if constraintErr := checkDecodedLength(opts, sd78d83_29, "37.4", "lMsId", "SIZE (4)", len(*v.LMsId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode dialledNumber
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "dialledNumber", content[offset:])
				decodedTag_diallednumber, n_diallednumber, rawVal_diallednumber, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "dialledNumber", "decoding", false)
				}
				if decodedTag_diallednumber.Class != tag.ClassContextSpecific || decodedTag_diallednumber.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_diallednumber), "dialledNumber", "decoding", false)
				}
				decVal_diallednumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_diallednumber.Constructed, rawVal_diallednumber, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "dialledNumber", "decoding", false)
				}
				tmp_diallednumber := IsdnAddressString(decVal_diallednumber)
				v.DialledNumber = &tmp_diallednumber
				if offset < 0 || offset >
					len(content) || n_diallednumber < 0 || n_diallednumber > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_diallednumber
				if len(*v.DialledNumber) < 1 || len(*v.DialledNumber) > 10 {
					if constraintErr := checkDecodedLength(opts, sd78d83_29, "37.4", "dialledNumber", "SIZE (1..10)", len(*v.DialledNumber)); constraintErr != nil {
						return constraintErr
					}
				}
				if len(*v.DialledNumber) < 1 || len(*v.DialledNumber) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_29, "37.4", "dialledNumber", "SIZE (1..20)", len(*v.DialledNumber)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode cug-Interlock
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 6 {
				ber.MarkPreflightTarget(opts, "cug-Interlock", content[offset:])
				decodedTag_cuginterlock, n_cuginterlock, rawVal_cuginterlock, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cug-Interlock", "decoding", false)
				}
				if decodedTag_cuginterlock.Class != tag.ClassContextSpecific || decodedTag_cuginterlock.Number != 6 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_cuginterlock), "cug-Interlock", "decoding", false)
				}
				decVal_cuginterlock, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cuginterlock.Constructed, rawVal_cuginterlock, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "cug-Interlock", "decoding", false)
				}
				tmp_cuginterlock := CUGInterlock(decVal_cuginterlock)
				v.CugInterlock = &tmp_cuginterlock
				if offset < 0 || offset >
					len(content) || n_cuginterlock < 0 || n_cuginterlock > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cuginterlock
				if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
					if constraintErr := checkDecodedLength(opts, sd78d83_29, "37.4", "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode numberOfForwarding
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 7 {
				ber.MarkPreflightTarget(opts, "numberOfForwarding", content[offset:])
				decodedTag_numberofforwarding, n_numberofforwarding, rawVal_numberofforwarding, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "numberOfForwarding", "decoding", false)
				}
				if decodedTag_numberofforwarding.Class != tag.ClassContextSpecific || decodedTag_numberofforwarding.Number != 7 {
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
					len(content) || n_numberofforwarding < 0 || n_numberofforwarding > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_numberofforwarding
				if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
					if constraintErr := checkDecodedValue(opts, sd78d83_29, "37.3", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SendInfoForIncomingCallArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SendInfoForOutgoingCallArgument to BER format.
func (v *SendInfoForOutgoingCallArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendInfoForOutgoingCallArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendInfoForOutgoingCallArgument).MarshalBER, (*SendInfoForOutgoingCallArgument).marshalBER, 3)

}
func (v *SendInfoForOutgoingCallArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.CalledNumber) < 1 || len(v.CalledNumber) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_30, "37.4", "calledNumber", "SIZE (1..10)", len(v.CalledNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.CalledNumber) < 1 || len(v.CalledNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_30, "37.4", "calledNumber", "SIZE (1..20)", len(v.CalledNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callednumber, encodeErr_enc_callednumber := ber.EncodeOctetString([]byte(v.CalledNumber))
	if encodeErr_enc_callednumber != nil {
		return nil, qualifyBERError(encodeErr_enc_callednumber, "calledNumber", "encoding", false)
	}
	retagged_enc_callednumber, tagErr_enc_callednumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callednumber)
	if tagErr_enc_callednumber != nil {
		return nil, qualifyBERError(tagErr_enc_callednumber, "calledNumber", "encoding", false)
	}
	enc_callednumber = retagged_enc_callednumber
	children = append(children, enc_callednumber...)
	if v.BearerService != nil {
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_30, "37.4", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservice, encodeErr_enc_bearerservice := ber.EncodeOctetString([]byte(*v.BearerService))
		if encodeErr_enc_bearerservice != nil {
			return nil, qualifyBERError(encodeErr_enc_bearerservice, "bearerService", "encoding", false)
		}
		retagged_enc_bearerservice, tagErr_enc_bearerservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_bearerservice)
		if tagErr_enc_bearerservice != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservice, "bearerService", "encoding", false)
		}
		enc_bearerservice = retagged_enc_bearerservice
		children = append(children, enc_bearerservice...)
	}
	if v.TeleService != nil {
		if len(*v.TeleService) < 1 || len(*v.TeleService) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_30, "37.4", "teleService", "SIZE (1)", len(*v.TeleService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(*v.TeleService))
		if encodeErr_enc_teleservice != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservice, "teleService", "encoding", false)
		}
		retagged_enc_teleservice, tagErr_enc_teleservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_teleservice)
		if tagErr_enc_teleservice != nil {
			return nil, qualifyBERError(tagErr_enc_teleservice, "teleService", "encoding", false)
		}
		enc_teleservice = retagged_enc_teleservice
		children = append(children, enc_teleservice...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendInfoForOutgoingCallArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendInfoForOutgoingCallArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendInfoForOutgoingCallArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendInfoForOutgoingCallArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.CalledNumber) < 1 || len(v.CalledNumber) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_30, "37.4", "calledNumber", "SIZE (1..10)", len(v.CalledNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.CalledNumber) < 1 || len(v.CalledNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_30, "37.4", "calledNumber", "SIZE (1..20)", len(v.CalledNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_callednumber, encodeErr_enc_callednumber := ber.EncodeOctetString([]byte(v.CalledNumber))
	if encodeErr_enc_callednumber != nil {
		return nil, qualifyBERError(encodeErr_enc_callednumber, "calledNumber", "encoding", true)
	}
	retagged_enc_callednumber, tagErr_enc_callednumber := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_callednumber)
	if tagErr_enc_callednumber != nil {
		return nil, qualifyBERError(tagErr_enc_callednumber, "calledNumber", "encoding", true)
	}
	enc_callednumber = retagged_enc_callednumber
	children = append(children, enc_callednumber...)
	if v.BearerService != nil {
		if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_30, "37.4", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_bearerservice, encodeErr_enc_bearerservice := ber.EncodeOctetString([]byte(*v.BearerService))
		if encodeErr_enc_bearerservice != nil {
			return nil, qualifyBERError(encodeErr_enc_bearerservice, "bearerService", "encoding", true)
		}
		retagged_enc_bearerservice, tagErr_enc_bearerservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_bearerservice)
		if tagErr_enc_bearerservice != nil {
			return nil, qualifyBERError(tagErr_enc_bearerservice, "bearerService", "encoding", true)
		}
		enc_bearerservice = retagged_enc_bearerservice
		children = append(children, enc_bearerservice...)
	}
	if v.TeleService != nil {
		if len(*v.TeleService) < 1 || len(*v.TeleService) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_30, "37.4", "teleService", "SIZE (1)", len(*v.TeleService)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservice, encodeErr_enc_teleservice := ber.EncodeOctetString([]byte(*v.TeleService))
		if encodeErr_enc_teleservice != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservice, "teleService", "encoding", true)
		}
		retagged_enc_teleservice, tagErr_enc_teleservice := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_teleservice)
		if tagErr_enc_teleservice != nil {
			return nil, qualifyBERError(tagErr_enc_teleservice, "teleService", "encoding", true)
		}
		enc_teleservice = retagged_enc_teleservice
		children = append(children, enc_teleservice...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendInfoForOutgoingCallArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendInfoForOutgoingCallArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendInfoForOutgoingCallArgument from BER/DER format.
func (destination *SendInfoForOutgoingCallArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendInfoForOutgoingCallArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendInfoForOutgoingCallArgument)

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
			var probe SendInfoForOutgoingCallArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_30, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendInfoForOutgoingCallArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendInfoForOutgoingCallArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendInfoForOutgoingCallArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendInfoForOutgoingCallArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode calledNumber
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field calledNumber", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("%w: expected tag [%s %d] for calledNumber, got %s", ber.ErrUnexpectedElement, "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "calledNumber", content[offset:])
		decodedTag_callednumber, n_callednumber, rawVal_callednumber, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "calledNumber", "decoding", false)
		}
		if decodedTag_callednumber.Class != tag.ClassContextSpecific || decodedTag_callednumber.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_callednumber), "calledNumber", "decoding", false)
		}
		decVal_callednumber, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_callednumber.Constructed, rawVal_callednumber, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "calledNumber", "decoding", false)
		}
		v.CalledNumber = IsdnAddressString(decVal_callednumber)
		if offset > len(content) || n_callednumber < 0 || n_callednumber > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_callednumber
		if len(v.CalledNumber) < 1 || len(v.CalledNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_30, "37.4", "calledNumber", "SIZE (1..10)", len(v.CalledNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.CalledNumber) < 1 || len(v.CalledNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_30, "37.4", "calledNumber", "SIZE (1..20)", len(v.CalledNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode bearerService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 2 {
				ber.MarkPreflightTarget(opts, "bearerService", content[offset:])
				decodedTag_bearerservice, n_bearerservice, rawVal_bearerservice, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "bearerService", "decoding", false)
				}
				if decodedTag_bearerservice.Class != tag.ClassContextSpecific || decodedTag_bearerservice.Number != 2 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_bearerservice), "bearerService", "decoding", false)
				}
				decVal_bearerservice, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_bearerservice.Constructed, rawVal_bearerservice, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "bearerService", "decoding", false)
				}
				tmp_bearerservice := BearerServiceCode(decVal_bearerservice)
				v.BearerService = &tmp_bearerservice
				if offset < 0 || offset >
					len(content) || n_bearerservice < 0 || n_bearerservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_bearerservice
				if len(*v.BearerService) < 1 || len(*v.BearerService) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_30, "37.4", "bearerService", "SIZE (1)", len(*v.BearerService)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode teleService
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "teleService", content[offset:])
				decodedTag_teleservice, n_teleservice, rawVal_teleservice, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "teleService", "decoding", false)
				}
				if decodedTag_teleservice.Class != tag.ClassContextSpecific || decodedTag_teleservice.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_teleservice), "teleService", "decoding", false)
				}
				decVal_teleservice, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_teleservice.Constructed, rawVal_teleservice, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "teleService", "decoding", false)
				}
				tmp_teleservice := TeleserviceCode(decVal_teleservice)
				v.TeleService = &tmp_teleservice
				if offset < 0 || offset >
					len(content) || n_teleservice < 0 || n_teleservice > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_teleservice
				if len(*v.TeleService) < 1 || len(*v.TeleService) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_30, "37.4", "teleService", "SIZE (1)", len(*v.TeleService)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SendInfoForOutgoingCallArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SendParametersArgument to BER format.
func (v *SendParametersArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendParametersArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendParametersArgument).MarshalBER, (*SendParametersArgument).marshalBER, 3)

}
func (v *SendParametersArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_subscriberid, err := v.SubscriberId.MarshalBER(ber.ChildEncodeOptions(opts, "subscriberId")...)
	if err != nil {
		return nil, qualifyBERError(err, "subscriberId", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_subscriberid)
	children = append(children, enc_subscriberid...)
	if v.RequestParameters == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "requestParameters", "encoding", false)
	}
	if len((v.RequestParameters).Values) < 1 || len((v.RequestParameters).Values) > 2 {
		if constraintErr := checkEncodedLength(opts, sd78d83_31, "37.4", "requestParameters", "SIZE (1..2)", len((v.RequestParameters).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_requestparameters, err := MarshalBERRequestParameters(v.RequestParameters, ber.ParentCollectionSizeEncodeOptions(ber.ChildEncodeOptions(opts, "requestParameters"))...)
	if err != nil {
		return nil, qualifyBERError(err, "requestParameters", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_requestparameters)
	children = append(children, enc_requestparameters...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendParametersArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendParametersArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendParametersArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendParametersArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_subscriberid, err := v.SubscriberId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "subscriberId", "encoding", true)
	}
	children = append(children, enc_subscriberid...)
	if v.RequestParameters == nil {
		return nil, qualifyBERError(fmt.Errorf("%w: required collection is nil", ber.ErrInvalidValue), "requestParameters", "encoding", true)
	}
	if len((v.RequestParameters).Values) < 1 || len((v.RequestParameters).Values) > 2 {
		if constraintErr := checkEncodedLength(nil, sd78d83_31, "37.4", "requestParameters", "SIZE (1..2)", len((v.RequestParameters).Values)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_requestparameters, err := MarshalDERRequestParameters(v.RequestParameters)
	if err != nil {
		return nil, qualifyBERError(err, "requestParameters", "encoding", true)
	}
	children = append(children, enc_requestparameters...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendParametersArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendParametersArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendParametersArgument from BER/DER format.
func (destination *SendParametersArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendParametersArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendParametersArgument)

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
			var probe SendParametersArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_31, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendParametersArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendParametersArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendParametersArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendParametersArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode subscriberId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field subscriberId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "subscriberId", content[offset:])
		// Decode nested CHOICE (SubscriberId)
		_, n_subscriberid, _, tlvErr_subscriberid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_subscriberid != nil {
			return qualifyBERError(tlvErr_subscriberid, "subscriberId", "decoding", false)
		}
		if offset > len(content) || n_subscriberid < 0 || n_subscriberid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.SubscriberId.UnmarshalBER(content[offset:offset+n_subscriberid], ber.ChildDecodeOptions(opts, "subscriberId")...); unmErr != nil {
			return qualifyBERError(unmErr, "subscriberId", "decoding", false)
		}
		if offset > len(content) || n_subscriberid < 0 || n_subscriberid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_subscriberid
	}
	// Decode requestParameters
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field requestParameters", ber.ErrUnexpectedElement)
	}
	{
		v.berRequestParametersIndef_ = false
		ber.MarkPreflightTarget(opts, "requestParameters", content[offset:])
		// Decode nested SEQUENCE_OF (RequestParameters)
		_, n_requestparameters, _, tlvErr_requestparameters := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_requestparameters != nil {
			return qualifyBERError(tlvErr_requestparameters, "requestParameters", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_requestparameters < 0 || n_requestparameters >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		tlv_requestparameters := content[offset : offset+n_requestparameters]
		{
			_, tagSz_, _ := ber.DecodeTag(tlv_requestparameters)
			if tagSz_ < len(tlv_requestparameters) && tlv_requestparameters[tagSz_] == 0x80 {
				v.berRequestParametersIndef_ = true
			}
		}
		dec_requestparameters, unmErr := UnmarshalBERRequestParameters(tlv_requestparameters, ber.ParentCollectionSizeDecodeOptions(ber.ChildDecodeOptions(opts, "requestParameters"))...)
		if unmErr != nil {
			return qualifyBERError(unmErr, "requestParameters", "decoding", false)
		}
		v.RequestParameters = dec_requestparameters
		if offset < 0 || offset >
			len(content) || n_requestparameters < 0 || n_requestparameters >
			len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_requestparameters
		if len((v.RequestParameters).Values) < 1 || len((v.RequestParameters).Values) > 2 {
			if constraintErr := checkDecodedLength(opts, sd78d83_31, "37.4", "requestParameters", "SIZE (1..2)", len((v.RequestParameters).Values)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SendParametersArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SendRoutingInfoForSMArgument to BER format.
func (v *SendRoutingInfoForSMArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoForSMArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendRoutingInfoForSMArgument).MarshalBER, (*SendRoutingInfoForSMArgument).marshalBER, 3)

}
func (v *SendRoutingInfoForSMArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_32, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_32, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", false)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msIsdn", "encoding", false)
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
		if constraintErr := checkEncodedLength(opts, sd78d83_32, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
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
	if v.CugInterlock != nil {
		if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
			if constraintErr := checkEncodedLength(opts, sd78d83_32, "37.4", "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
		if encodeErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", false)
		}
		retagged_enc_cuginterlock, tagErr_enc_cuginterlock := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_cuginterlock)
		if tagErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(tagErr_enc_cuginterlock, "cug-Interlock", "encoding", false)
		}
		enc_cuginterlock = retagged_enc_cuginterlock
		children = append(children, enc_cuginterlock...)
	}
	if v.TeleserviceCode != nil {
		if len(*v.TeleserviceCode) < 1 || len(*v.TeleserviceCode) > 1 {
			if constraintErr := checkEncodedLength(opts, sd78d83_32, "37.4", "teleserviceCode", "SIZE (1)", len(*v.TeleserviceCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicecode, encodeErr_enc_teleservicecode := ber.EncodeOctetString([]byte(*v.TeleserviceCode))
		if encodeErr_enc_teleservicecode != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservicecode, "teleserviceCode", "encoding", false)
		}
		retagged_enc_teleservicecode, tagErr_enc_teleservicecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_teleservicecode)
		if tagErr_enc_teleservicecode != nil {
			return nil, qualifyBERError(tagErr_enc_teleservicecode, "teleserviceCode", "encoding", false)
		}
		enc_teleservicecode = retagged_enc_teleservicecode
		children = append(children, enc_teleservicecode...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendRoutingInfoForSMArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendRoutingInfoForSMArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendRoutingInfoForSMArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoForSMArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_32, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_32, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", true)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msIsdn", "encoding", true)
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
		if constraintErr := checkEncodedLength(nil, sd78d83_32, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
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
	if v.CugInterlock != nil {
		if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
			if constraintErr := checkEncodedLength(nil, sd78d83_32, "37.4", "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
		if encodeErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", true)
		}
		retagged_enc_cuginterlock, tagErr_enc_cuginterlock := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_cuginterlock)
		if tagErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(tagErr_enc_cuginterlock, "cug-Interlock", "encoding", true)
		}
		enc_cuginterlock = retagged_enc_cuginterlock
		children = append(children, enc_cuginterlock...)
	}
	if v.TeleserviceCode != nil {
		if len(*v.TeleserviceCode) < 1 || len(*v.TeleserviceCode) > 1 {
			if constraintErr := checkEncodedLength(nil, sd78d83_32, "37.4", "teleserviceCode", "SIZE (1)", len(*v.TeleserviceCode)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_teleservicecode, encodeErr_enc_teleservicecode := ber.EncodeOctetString([]byte(*v.TeleserviceCode))
		if encodeErr_enc_teleservicecode != nil {
			return nil, qualifyBERError(encodeErr_enc_teleservicecode, "teleserviceCode", "encoding", true)
		}
		retagged_enc_teleservicecode, tagErr_enc_teleservicecode := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 5, enc_teleservicecode)
		if tagErr_enc_teleservicecode != nil {
			return nil, qualifyBERError(tagErr_enc_teleservicecode, "teleserviceCode", "encoding", true)
		}
		enc_teleservicecode = retagged_enc_teleservicecode
		children = append(children, enc_teleservicecode...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendRoutingInfoForSMArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendRoutingInfoForSMArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendRoutingInfoForSMArgument from BER/DER format.
func (destination *SendRoutingInfoForSMArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendRoutingInfoForSMArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendRoutingInfoForSMArgument)

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
			var probe SendRoutingInfoForSMArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_32, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendRoutingInfoForSMArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendRoutingInfoForSMArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInfoForSMArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInfoForSMArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msIsdn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field msIsdn", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("%w: expected tag [%s %d] for msIsdn, got %s", ber.ErrUnexpectedElement, "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "msIsdn", content[offset:])
		decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msIsdn", "decoding", false)
		}
		if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_msisdn), "msIsdn", "decoding", false)
		}
		decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msIsdn", "decoding", false)
		}
		v.MsIsdn = IsdnAddressString(decVal_msisdn)
		if offset > len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_msisdn
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_32, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_32, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
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
			if constraintErr := checkDecodedLength(opts, sd78d83_32, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cug-Interlock
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "cug-Interlock", content[offset:])
				decodedTag_cuginterlock, n_cuginterlock, rawVal_cuginterlock, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cug-Interlock", "decoding", false)
				}
				if decodedTag_cuginterlock.Class != tag.ClassContextSpecific || decodedTag_cuginterlock.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_cuginterlock), "cug-Interlock", "decoding", false)
				}
				decVal_cuginterlock, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cuginterlock.Constructed, rawVal_cuginterlock, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "cug-Interlock", "decoding", false)
				}
				tmp_cuginterlock := CUGInterlock(decVal_cuginterlock)
				v.CugInterlock = &tmp_cuginterlock
				if offset < 0 || offset >
					len(content) || n_cuginterlock < 0 || n_cuginterlock > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cuginterlock
				if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
					if constraintErr := checkDecodedLength(opts, sd78d83_32, "37.4", "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode teleserviceCode
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 5 {
				ber.MarkPreflightTarget(opts, "teleserviceCode", content[offset:])
				decodedTag_teleservicecode, n_teleservicecode, rawVal_teleservicecode, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "teleserviceCode", "decoding", false)
				}
				if decodedTag_teleservicecode.Class != tag.ClassContextSpecific || decodedTag_teleservicecode.Number != 5 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_teleservicecode), "teleserviceCode", "decoding", false)
				}
				decVal_teleservicecode, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_teleservicecode.Constructed, rawVal_teleservicecode, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "teleserviceCode", "decoding", false)
				}
				tmp_teleservicecode := TeleserviceCode(decVal_teleservicecode)
				v.TeleserviceCode = &tmp_teleservicecode
				if offset < 0 || offset >
					len(content) || n_teleservicecode < 0 || n_teleservicecode > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_teleservicecode
				if len(*v.TeleserviceCode) < 1 || len(*v.TeleserviceCode) > 1 {
					if constraintErr := checkDecodedLength(opts, sd78d83_32, "37.4", "teleserviceCode", "SIZE (1)", len(*v.TeleserviceCode)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoForSMArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SendRoutingInfoForSMResult to BER format.
func (v *SendRoutingInfoForSMResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoForSMResult receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendRoutingInfoForSMResult).MarshalBER, (*SendRoutingInfoForSMResult).marshalBER, 3)

}
func (v *SendRoutingInfoForSMResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, sd78d83_33, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	enc_component1, err := v.Component1.MarshalBER(ber.ChildEncodeOptions(opts, "component1")...)
	if err != nil {
		return nil, qualifyBERError(err, "component1", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_component1)
	children = append(children, enc_component1...)
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
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendRoutingInfoForSMResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendRoutingInfoForSMResult to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendRoutingInfoForSMResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoForSMResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, sd78d83_33, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	enc_component1, err := v.Component1.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "component1", "encoding", true)
	}
	children = append(children, enc_component1...)
	if v.MwdSet != nil {
		enc_mwdset := ber.EncodeBoolean(*v.MwdSet)
		retagged_enc_mwdset, tagErr_enc_mwdset := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_mwdset)
		if tagErr_enc_mwdset != nil {
			return nil, qualifyBERError(tagErr_enc_mwdset, "mwd-Set", "encoding", true)
		}
		enc_mwdset = retagged_enc_mwdset
		children = append(children, enc_mwdset...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendRoutingInfoForSMResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendRoutingInfoForSMResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendRoutingInfoForSMResult from BER/DER format.
func (destination *SendRoutingInfoForSMResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendRoutingInfoForSMResult destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendRoutingInfoForSMResult)

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
			var probe SendRoutingInfoForSMResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_33, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendRoutingInfoForSMResult{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendRoutingInfoForSMResult).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInfoForSMResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInfoForSMResult", Cause: ber.ErrExtraData}
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
		if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, sd78d83_33, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
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
		// Decode nested CHOICE (SendRoutingInfoForSMResultComponent1)
		_, n_component1, _, tlvErr_component1 := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_component1 != nil {
			return qualifyBERError(tlvErr_component1, "component1", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_component1 < 0 || n_component1 > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.Component1.UnmarshalBER(content[offset:offset+n_component1], ber.ChildDecodeOptions(opts, "component1")...); unmErr != nil {
			return qualifyBERError(unmErr, "component1", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_component1 < 0 || n_component1 > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_component1
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
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoForSMResult", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SendRoutingInformationArgument to BER format.
func (v *SendRoutingInformationArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInformationArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendRoutingInformationArgument).MarshalBER, (*SendRoutingInformationArgument).marshalBER, 3)

}
func (v *SendRoutingInformationArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_34, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_34, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", false)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msIsdn", "encoding", false)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if v.CugInterlock != nil {
		if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
			if constraintErr := checkEncodedLength(opts, sd78d83_34, "37.4", "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
		if encodeErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", false)
		}
		retagged_enc_cuginterlock, tagErr_enc_cuginterlock := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cuginterlock)
		if tagErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(tagErr_enc_cuginterlock, "cug-Interlock", "encoding", false)
		}
		enc_cuginterlock = retagged_enc_cuginterlock
		children = append(children, enc_cuginterlock...)
	}
	if v.NumberOfForwarding != nil {
		if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
			if constraintErr := checkEncodedValue(opts, sd78d83_34, "37.3", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
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
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendRoutingInformationArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendRoutingInformationArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendRoutingInformationArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInformationArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_34, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_34, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", true)
	}
	retagged_enc_msisdn, tagErr_enc_msisdn := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_msisdn)
	if tagErr_enc_msisdn != nil {
		return nil, qualifyBERError(tagErr_enc_msisdn, "msIsdn", "encoding", true)
	}
	enc_msisdn = retagged_enc_msisdn
	children = append(children, enc_msisdn...)
	if v.CugInterlock != nil {
		if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
			if constraintErr := checkEncodedLength(nil, sd78d83_34, "37.4", "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_cuginterlock, encodeErr_enc_cuginterlock := ber.EncodeOctetString([]byte(*v.CugInterlock))
		if encodeErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(encodeErr_enc_cuginterlock, "cug-Interlock", "encoding", true)
		}
		retagged_enc_cuginterlock, tagErr_enc_cuginterlock := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_cuginterlock)
		if tagErr_enc_cuginterlock != nil {
			return nil, qualifyBERError(tagErr_enc_cuginterlock, "cug-Interlock", "encoding", true)
		}
		enc_cuginterlock = retagged_enc_cuginterlock
		children = append(children, enc_cuginterlock...)
	}
	if v.NumberOfForwarding != nil {
		if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
			if constraintErr := checkEncodedValue(nil, sd78d83_34, "37.3", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendRoutingInformationArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendRoutingInformationArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendRoutingInformationArgument from BER/DER format.
func (destination *SendRoutingInformationArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendRoutingInformationArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendRoutingInformationArgument)

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
			var probe SendRoutingInformationArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_34, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendRoutingInformationArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendRoutingInformationArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInformationArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInformationArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msIsdn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field msIsdn", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 0 {
			return fmt.Errorf("%w: expected tag [%s %d] for msIsdn, got %s", ber.ErrUnexpectedElement, "CONTEXT", 0, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "msIsdn", content[offset:])
		decodedTag_msisdn, n_msisdn, rawVal_msisdn, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msIsdn", "decoding", false)
		}
		if decodedTag_msisdn.Class != tag.ClassContextSpecific || decodedTag_msisdn.Number != 0 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_msisdn), "msIsdn", "decoding", false)
		}
		decVal_msisdn, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_msisdn.Constructed, rawVal_msisdn, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "msIsdn", "decoding", false)
		}
		v.MsIsdn = IsdnAddressString(decVal_msisdn)
		if offset > len(content) || n_msisdn < 0 || n_msisdn > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_msisdn
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_34, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_34, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cug-Interlock
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
				ber.MarkPreflightTarget(opts, "cug-Interlock", content[offset:])
				decodedTag_cuginterlock, n_cuginterlock, rawVal_cuginterlock, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "cug-Interlock", "decoding", false)
				}
				if decodedTag_cuginterlock.Class != tag.ClassContextSpecific || decodedTag_cuginterlock.Number != 1 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_cuginterlock), "cug-Interlock", "decoding", false)
				}
				decVal_cuginterlock, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_cuginterlock.Constructed, rawVal_cuginterlock, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "cug-Interlock", "decoding", false)
				}
				tmp_cuginterlock := CUGInterlock(decVal_cuginterlock)
				v.CugInterlock = &tmp_cuginterlock
				if offset < 0 || offset >
					len(content) || n_cuginterlock < 0 || n_cuginterlock > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_cuginterlock
				if len(*v.CugInterlock) < 4 || len(*v.CugInterlock) > 4 {
					if constraintErr := checkDecodedLength(opts, sd78d83_34, "37.4", "cug-Interlock", "SIZE (4)", len(*v.CugInterlock)); constraintErr != nil {
						return constraintErr
					}
				}
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
					len(content) || n_numberofforwarding < 0 || n_numberofforwarding > len(
					content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_numberofforwarding
				if !(int64(*v.NumberOfForwarding) >= 1 && int64(*v.NumberOfForwarding) <= 5) {
					if constraintErr := checkDecodedValue(opts, sd78d83_34, "37.3", "numberOfForwarding", "(1..5)", ber.ObserveInteger(int64(*v.NumberOfForwarding))); constraintErr != nil {
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
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo > len(content[offset:]) {
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
					len(content) || n_networksignalinfo < 0 || n_networksignalinfo > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_networksignalinfo
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInformationArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SendRoutingInformationResult to BER format.
func (v *SendRoutingInformationResult) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInformationResult receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendRoutingInformationResult).MarshalBER, (*SendRoutingInformationResult).marshalBER, 3)

}
func (v *SendRoutingInformationResult) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, sd78d83_35, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
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
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendRoutingInformationResult) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendRoutingInformationResult to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendRoutingInformationResult) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInformationResult receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, sd78d83_35, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
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
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendRoutingInformationResult as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendRoutingInformationResult) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendRoutingInformationResult from BER/DER format.
func (destination *SendRoutingInformationResult) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendRoutingInformationResult destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendRoutingInformationResult)

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
			var probe SendRoutingInformationResult
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_35, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendRoutingInformationResult{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendRoutingInformationResult).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInformationResult SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInformationResult", Cause: ber.ErrExtraData}
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
		if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, sd78d83_35, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
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
		// Decode nested CHOICE (SendRoutingInformationResultRoutingInfo)
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
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInformationResult", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SetCipheringModeArgument to BER format.
func (v *SetCipheringModeArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SetCipheringModeArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SetCipheringModeArgument).MarshalBER, (*SetCipheringModeArgument).marshalBER, 3)

}
func (v *SetCipheringModeArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if int64(v.CipheringMode) != 1 && int64(v.CipheringMode) != 2 {
		if constraintErr := checkEncodedValue(opts, sd78d83_36, "15", "cipheringMode", "ENUMERATED {1, 2}", ber.ObserveInteger(int64(v.CipheringMode))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cipheringmode := ber.EncodeEnumerated(int64(v.CipheringMode))
	children = append(children, enc_cipheringmode...)
	if v.Kc != nil {
		if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
			if constraintErr := checkEncodedLength(opts, sd78d83_36, "37.4", "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(*v.Kc))
		if encodeErr_enc_kc != nil {
			return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", false)
		}
		children = append(children, enc_kc...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SetCipheringModeArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SetCipheringModeArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SetCipheringModeArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SetCipheringModeArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if int64(v.CipheringMode) != 1 && int64(v.CipheringMode) != 2 {
		if constraintErr := checkEncodedValue(nil, sd78d83_36, "15", "cipheringMode", "ENUMERATED {1, 2}", ber.ObserveInteger(int64(v.CipheringMode))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cipheringmode := ber.EncodeEnumerated(int64(v.CipheringMode))
	children = append(children, enc_cipheringmode...)
	if v.Kc != nil {
		if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
			if constraintErr := checkEncodedLength(nil, sd78d83_36, "37.4", "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_kc, encodeErr_enc_kc := ber.EncodeOctetString([]byte(*v.Kc))
		if encodeErr_enc_kc != nil {
			return nil, qualifyBERError(encodeErr_enc_kc, "kc", "encoding", true)
		}
		children = append(children, enc_kc...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SetCipheringModeArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SetCipheringModeArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SetCipheringModeArgument from BER/DER format.
func (destination *SetCipheringModeArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SetCipheringModeArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(SetCipheringModeArgument)

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
			var probe SetCipheringModeArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_36, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SetCipheringModeArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SetCipheringModeArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SetCipheringModeArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SetCipheringModeArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode cipheringMode
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cipheringMode", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cipheringMode", content[offset:])
		val_cipheringmode, n, err := ber.DecodeEnumerated(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cipheringMode", "decoding", false)
		}
		v.CipheringMode = CipheringMode(val_cipheringmode)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if int64(v.CipheringMode) != 1 && int64(v.CipheringMode) != 2 {
			if constraintErr := checkDecodedValue(opts, sd78d83_36, "15", "cipheringMode", "ENUMERATED {1, 2}", ber.ObserveInteger(int64(v.CipheringMode))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode kc
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "kc", content[offset:])
				val_kc, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "kc", "decoding", false)
				}
				tmp_kc := Kc(val_kc)
				v.Kc = &tmp_kc
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.Kc) < 8 || len(*v.Kc) > 8 {
					if constraintErr := checkDecodedLength(opts, sd78d83_36, "37.4", "kc", "SIZE (8)", len(*v.Kc)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SetCipheringModeArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SetMessageWaitingDataArgument to BER format.
func (v *SetMessageWaitingDataArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SetMessageWaitingDataArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SetMessageWaitingDataArgument).MarshalBER, (*SetMessageWaitingDataArgument).marshalBER, 3)

}
func (v *SetMessageWaitingDataArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_37, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_37, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", false)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_37, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", false)
	}
	children = append(children, enc_servicecentreaddress...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SetMessageWaitingDataArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SetMessageWaitingDataArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SetMessageWaitingDataArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SetMessageWaitingDataArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_37, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_37, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_msisdn, encodeErr_enc_msisdn := ber.EncodeOctetString([]byte(v.MsIsdn))
	if encodeErr_enc_msisdn != nil {
		return nil, qualifyBERError(encodeErr_enc_msisdn, "msIsdn", "encoding", true)
	}
	children = append(children, enc_msisdn...)
	if len(v.ServiceCentreAddress) < 1 || len(v.ServiceCentreAddress) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_37, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_servicecentreaddress, encodeErr_enc_servicecentreaddress := ber.EncodeOctetString([]byte(v.ServiceCentreAddress))
	if encodeErr_enc_servicecentreaddress != nil {
		return nil, qualifyBERError(encodeErr_enc_servicecentreaddress, "serviceCentreAddress", "encoding", true)
	}
	children = append(children, enc_servicecentreaddress...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SetMessageWaitingDataArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SetMessageWaitingDataArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SetMessageWaitingDataArgument from BER/DER format.
func (destination *SetMessageWaitingDataArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SetMessageWaitingDataArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(SetMessageWaitingDataArgument)

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
			var probe SetMessageWaitingDataArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_37, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SetMessageWaitingDataArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SetMessageWaitingDataArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SetMessageWaitingDataArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SetMessageWaitingDataArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode msIsdn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field msIsdn", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "msIsdn", content[offset:])
		val_msisdn, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "msIsdn", "decoding", false)
		}
		v.MsIsdn = IsdnAddressString(val_msisdn)
		if offset > len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_37, "37.4", "msIsdn", "SIZE (1..10)", len(v.MsIsdn)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.MsIsdn) < 1 || len(v.MsIsdn) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_37, "37.4", "msIsdn", "SIZE (1..20)", len(v.MsIsdn)); constraintErr != nil {
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
			if constraintErr := checkDecodedLength(opts, sd78d83_37, "37.4", "serviceCentreAddress", "SIZE (1..20)", len(v.ServiceCentreAddress)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SetMessageWaitingDataArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes TraceSubscriberActivityArgument to BER format.
func (v *TraceSubscriberActivityArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: TraceSubscriberActivityArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*TraceSubscriberActivityArgument).MarshalBER, (*TraceSubscriberActivityArgument).marshalBER, 3)

}
func (v *TraceSubscriberActivityArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, sd78d83_38, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", false)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := checkEncodedLength(opts, sd78d83_38, "37.4", "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", false)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", false)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := checkEncodedValue(opts, sd78d83_38, "37.3", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", false)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_38, "37.4", "omcId", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_omcid, encodeErr_enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		if encodeErr_enc_omcid != nil {
			return nil, qualifyBERError(encodeErr_enc_omcid, "omcId", "encoding", false)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, qualifyBERError(tagErr_enc_omcid, "omcId", "encoding", false)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	if v.CallReference != nil {
		if len(*v.CallReference) < 1 || len(*v.CallReference) > 3 {
			if constraintErr := checkEncodedLength(opts, sd78d83_38, "37.4", "callReference", "SIZE (1..3)", len(*v.CallReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callreference, encodeErr_enc_callreference := ber.EncodeOctetString([]byte(*v.CallReference))
		if encodeErr_enc_callreference != nil {
			return nil, qualifyBERError(encodeErr_enc_callreference, "callReference", "encoding", false)
		}
		retagged_enc_callreference, tagErr_enc_callreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_callreference)
		if tagErr_enc_callreference != nil {
			return nil, qualifyBERError(tagErr_enc_callreference, "callReference", "encoding", false)
		}
		enc_callreference = retagged_enc_callreference
		children = append(children, enc_callreference...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *TraceSubscriberActivityArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes TraceSubscriberActivityArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *TraceSubscriberActivityArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: TraceSubscriberActivityArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if v.Imsi != nil {
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(nil, sd78d83_38, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_imsi != nil {
			return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
		}
		retagged_enc_imsi, tagErr_enc_imsi := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_imsi)
		if tagErr_enc_imsi != nil {
			return nil, qualifyBERError(tagErr_enc_imsi, "imsi", "encoding", true)
		}
		enc_imsi = retagged_enc_imsi
		children = append(children, enc_imsi...)
	}
	if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
		if constraintErr := checkEncodedLength(nil, sd78d83_38, "37.4", "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracereference, encodeErr_enc_tracereference := ber.EncodeOctetString([]byte(v.TraceReference))
	if encodeErr_enc_tracereference != nil {
		return nil, qualifyBERError(encodeErr_enc_tracereference, "traceReference", "encoding", true)
	}
	retagged_enc_tracereference, tagErr_enc_tracereference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_tracereference)
	if tagErr_enc_tracereference != nil {
		return nil, qualifyBERError(tagErr_enc_tracereference, "traceReference", "encoding", true)
	}
	enc_tracereference = retagged_enc_tracereference
	children = append(children, enc_tracereference...)
	if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
		if constraintErr := checkEncodedValue(nil, sd78d83_38, "37.3", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_tracetype := ber.EncodeInteger(int64(v.TraceType))
	retagged_enc_tracetype, tagErr_enc_tracetype := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 2, enc_tracetype)
	if tagErr_enc_tracetype != nil {
		return nil, qualifyBERError(tagErr_enc_tracetype, "traceType", "encoding", true)
	}
	enc_tracetype = retagged_enc_tracetype
	children = append(children, enc_tracetype...)
	if v.OmcId != nil {
		if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
			if constraintErr := checkEncodedLength(nil, sd78d83_38, "37.4", "omcId", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_omcid, encodeErr_enc_omcid := ber.EncodeOctetString([]byte(*v.OmcId))
		if encodeErr_enc_omcid != nil {
			return nil, qualifyBERError(encodeErr_enc_omcid, "omcId", "encoding", true)
		}
		retagged_enc_omcid, tagErr_enc_omcid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 3, enc_omcid)
		if tagErr_enc_omcid != nil {
			return nil, qualifyBERError(tagErr_enc_omcid, "omcId", "encoding", true)
		}
		enc_omcid = retagged_enc_omcid
		children = append(children, enc_omcid...)
	}
	if v.CallReference != nil {
		if len(*v.CallReference) < 1 || len(*v.CallReference) > 3 {
			if constraintErr := checkEncodedLength(nil, sd78d83_38, "37.4", "callReference", "SIZE (1..3)", len(*v.CallReference)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_callreference, encodeErr_enc_callreference := ber.EncodeOctetString([]byte(*v.CallReference))
		if encodeErr_enc_callreference != nil {
			return nil, qualifyBERError(encodeErr_enc_callreference, "callReference", "encoding", true)
		}
		retagged_enc_callreference, tagErr_enc_callreference := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 4, enc_callreference)
		if tagErr_enc_callreference != nil {
			return nil, qualifyBERError(tagErr_enc_callreference, "callReference", "encoding", true)
		}
		enc_callreference = retagged_enc_callreference
		children = append(children, enc_callreference...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding TraceSubscriberActivityArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *TraceSubscriberActivityArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes TraceSubscriberActivityArgument from BER/DER format.
func (destination *TraceSubscriberActivityArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: TraceSubscriberActivityArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(TraceSubscriberActivityArgument)

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
			var probe TraceSubscriberActivityArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_38, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = TraceSubscriberActivityArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*TraceSubscriberActivityArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding TraceSubscriberActivityArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "TraceSubscriberActivityArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode imsi
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
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
				tmp_imsi := IMSI(decVal_imsi)
				v.Imsi = &tmp_imsi
				if offset > len(content) || n_imsi < 0 || n_imsi > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_imsi
				if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
					if constraintErr := checkDecodedLength(opts, sd78d83_38, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode traceReference
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field traceReference", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 1 {
			return fmt.Errorf("%w: expected tag [%s %d] for traceReference, got %s", ber.ErrUnexpectedElement, "CONTEXT", 1, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "traceReference", content[offset:])
		decodedTag_tracereference, n_tracereference, rawVal_tracereference, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceReference", "decoding", false)
		}
		if decodedTag_tracereference.Class != tag.ClassContextSpecific || decodedTag_tracereference.Number != 1 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tracereference), "traceReference", "decoding", false)
		}
		decVal_tracereference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_tracereference.Constructed, rawVal_tracereference, opts...)
		if octetErr != nil {
			return qualifyBERError(octetErr, "traceReference", "decoding", false)
		}
		v.TraceReference = TraceReference(decVal_tracereference)
		if offset < 0 || offset >
			len(content) || n_tracereference < 0 || n_tracereference > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_tracereference
		if len(v.TraceReference) < 1 || len(v.TraceReference) > 2 {
			if constraintErr := checkDecodedLength(opts, sd78d83_38, "37.4", "traceReference", "SIZE (1..2)", len(v.TraceReference)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode traceType
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field traceType", ber.ErrUnexpectedElement)
	}
	if reqTag_, reqErr_ := ber.PeekTag(content[offset:]); reqErr_ == nil {
		if reqTag_.Class != tag.ClassContextSpecific || reqTag_.Number != 2 {
			return fmt.Errorf("%w: expected tag [%s %d] for traceType, got %s", ber.ErrUnexpectedElement, "CONTEXT", 2, reqTag_)
		}
	}
	{
		ber.MarkPreflightTarget(opts, "traceType", content[offset:])
		decodedTag_tracetype, n_tracetype, rawVal_tracetype, err := ber.DecodeTLV(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "traceType", "decoding", false)
		}
		if decodedTag_tracetype.Class != tag.ClassContextSpecific || decodedTag_tracetype.Number != 2 {
			return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_tracetype), "traceType", "decoding", false)
		}
		if decodedTag_tracetype.Constructed != false {
			return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, decodedTag_tracetype), "traceType", "decoding", false)
		}
		decVal_tracetype, intErr := ber.DecodeIntegerValue(rawVal_tracetype)
		if intErr != nil {
			return qualifyBERError(intErr, "traceType", "decoding", false)
		}
		v.TraceType = TraceType(decVal_tracetype)
		if offset < 0 || offset >
			len(content) || n_tracetype < 0 || n_tracetype > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_tracetype
		if !(int64(v.TraceType) >= 0 && int64(v.TraceType) <= 255) {
			if constraintErr := checkDecodedValue(opts, sd78d83_38, "37.3", "traceType", "(0..255)", ber.ObserveInteger(int64(v.TraceType))); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode omcId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 3 {
				ber.MarkPreflightTarget(opts, "omcId", content[offset:])
				decodedTag_omcid, n_omcid, rawVal_omcid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "omcId", "decoding", false)
				}
				if decodedTag_omcid.Class != tag.ClassContextSpecific || decodedTag_omcid.Number != 3 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_omcid), "omcId", "decoding", false)
				}
				decVal_omcid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_omcid.Constructed, rawVal_omcid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "omcId", "decoding", false)
				}
				tmp_omcid := AddressString(decVal_omcid)
				v.OmcId = &tmp_omcid
				if offset < 0 || offset >
					len(content) || n_omcid < 0 || n_omcid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_omcid
				if len(*v.OmcId) < 1 || len(*v.OmcId) > 20 {
					if constraintErr := checkDecodedLength(opts, sd78d83_38, "37.4", "omcId", "SIZE (1..20)", len(*v.OmcId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	// Decode callReference
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "callReference", content[offset:])
				decodedTag_callreference, n_callreference, rawVal_callreference, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "callReference", "decoding", false)
				}
				if decodedTag_callreference.Class != tag.ClassContextSpecific || decodedTag_callreference.Number != 4 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_callreference), "callReference", "decoding", false)
				}
				decVal_callreference, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_callreference.Constructed, rawVal_callreference, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "callReference", "decoding", false)
				}
				tmp_callreference := CallReference(decVal_callreference)
				v.CallReference = &tmp_callreference
				if offset < 0 || offset >
					len(content) || n_callreference < 0 || n_callreference > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_callreference
				if len(*v.CallReference) < 1 || len(*v.CallReference) > 3 {
					if constraintErr := checkDecodedLength(opts, sd78d83_38, "37.4", "callReference", "SIZE (1..3)", len(*v.CallReference)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "TraceSubscriberActivityArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes UpdateLocationArgument to BER format.
func (v *UpdateLocationArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: UpdateLocationArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*UpdateLocationArgument).MarshalBER, (*UpdateLocationArgument).marshalBER, 3)

}
func (v *UpdateLocationArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, sd78d83_39, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	enc_locationinfo, err := v.LocationInfo.MarshalBER(ber.ChildEncodeOptions(opts, "locationInfo")...)
	if err != nil {
		return nil, qualifyBERError(err, "locationInfo", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_locationinfo)
	children = append(children, enc_locationinfo...)
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 10 {
		if constraintErr := checkEncodedLength(opts, sd78d83_39, "37.4", "vlrNumber", "SIZE (1..10)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 20 {
		if constraintErr := checkEncodedLength(opts, sd78d83_39, "37.4", "vlrNumber", "SIZE (1..20)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_vlrnumber, encodeErr_enc_vlrnumber := ber.EncodeOctetString([]byte(v.VlrNumber))
	if encodeErr_enc_vlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_vlrnumber, "vlrNumber", "encoding", false)
	}
	children = append(children, enc_vlrnumber...)
	if v.LmsId != nil {
		if len(*v.LmsId) < 4 || len(*v.LmsId) > 4 {
			if constraintErr := checkEncodedLength(opts, sd78d83_39, "37.4", "lmsId", "SIZE (4)", len(*v.LmsId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsid, encodeErr_enc_lmsid := ber.EncodeOctetString([]byte(*v.LmsId))
		if encodeErr_enc_lmsid != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsid, "lmsId", "encoding", false)
		}
		retagged_enc_lmsid, tagErr_enc_lmsid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lmsid)
		if tagErr_enc_lmsid != nil {
			return nil, qualifyBERError(tagErr_enc_lmsid, "lmsId", "encoding", false)
		}
		enc_lmsid = retagged_enc_lmsid
		children = append(children, enc_lmsid...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *UpdateLocationArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes UpdateLocationArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *UpdateLocationArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UpdateLocationArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, sd78d83_39, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	enc_locationinfo, err := v.LocationInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "locationInfo", "encoding", true)
	}
	children = append(children, enc_locationinfo...)
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 10 {
		if constraintErr := checkEncodedLength(nil, sd78d83_39, "37.4", "vlrNumber", "SIZE (1..10)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 20 {
		if constraintErr := checkEncodedLength(nil, sd78d83_39, "37.4", "vlrNumber", "SIZE (1..20)", len(v.VlrNumber)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_vlrnumber, encodeErr_enc_vlrnumber := ber.EncodeOctetString([]byte(v.VlrNumber))
	if encodeErr_enc_vlrnumber != nil {
		return nil, qualifyBERError(encodeErr_enc_vlrnumber, "vlrNumber", "encoding", true)
	}
	children = append(children, enc_vlrnumber...)
	if v.LmsId != nil {
		if len(*v.LmsId) < 4 || len(*v.LmsId) > 4 {
			if constraintErr := checkEncodedLength(nil, sd78d83_39, "37.4", "lmsId", "SIZE (4)", len(*v.LmsId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsid, encodeErr_enc_lmsid := ber.EncodeOctetString([]byte(*v.LmsId))
		if encodeErr_enc_lmsid != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsid, "lmsId", "encoding", true)
		}
		retagged_enc_lmsid, tagErr_enc_lmsid := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 10, enc_lmsid)
		if tagErr_enc_lmsid != nil {
			return nil, qualifyBERError(tagErr_enc_lmsid, "lmsId", "encoding", true)
		}
		enc_lmsid = retagged_enc_lmsid
		children = append(children, enc_lmsid...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding UpdateLocationArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *UpdateLocationArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes UpdateLocationArgument from BER/DER format.
func (destination *UpdateLocationArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: UpdateLocationArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(UpdateLocationArgument)

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
			var probe UpdateLocationArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_39, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = UpdateLocationArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*UpdateLocationArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding UpdateLocationArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UpdateLocationArgument", Cause: ber.ErrExtraData}
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
		if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, sd78d83_39, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
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
		if offset < 0 || offset >
			len(content) || n_locationinfo < 0 || n_locationinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.LocationInfo.UnmarshalBER(content[offset:offset+n_locationinfo], ber.ChildDecodeOptions(opts, "locationInfo")...); unmErr != nil {
			return qualifyBERError(unmErr, "locationInfo", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_locationinfo < 0 || n_locationinfo > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_locationinfo
	}
	// Decode vlrNumber
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field vlrNumber", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "vlrNumber", content[offset:])
		val_vlrnumber, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "vlrNumber", "decoding", false)
		}
		v.VlrNumber = IsdnAddressString(val_vlrnumber)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_39, "37.4", "vlrNumber", "SIZE (1..10)", len(v.VlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(v.VlrNumber) < 1 || len(v.VlrNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_39, "37.4", "vlrNumber", "SIZE (1..20)", len(v.VlrNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode lmsId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 10 {
				ber.MarkPreflightTarget(opts, "lmsId", content[offset:])
				decodedTag_lmsid, n_lmsid, rawVal_lmsid, err := ber.DecodeTLV(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lmsId", "decoding", false)
				}
				if decodedTag_lmsid.Class != tag.ClassContextSpecific || decodedTag_lmsid.Number != 10 {
					return qualifyBERError(fmt.Errorf("%w: unexpected tag %s", ber.ErrUnexpectedElement, decodedTag_lmsid), "lmsId", "decoding", false)
				}
				decVal_lmsid, octetErr := ber.DecodeImplicitOctetStringValue(decodedTag_lmsid.Constructed, rawVal_lmsid, opts...)
				if octetErr != nil {
					return qualifyBERError(octetErr, "lmsId", "decoding", false)
				}
				tmp_lmsid := LMsId(decVal_lmsid)
				v.LmsId = &tmp_lmsid
				if offset < 0 || offset >
					len(content) || n_lmsid < 0 || n_lmsid > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n_lmsid
				if len(*v.LmsId) < 4 || len(*v.LmsId) > 4 {
					if constraintErr := checkDecodedLength(opts, sd78d83_39, "37.4", "lmsId", "SIZE (4)", len(*v.LmsId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "UpdateLocationArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes UpdateLocationAreaArgument to BER format.
func (v *UpdateLocationAreaArgument) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: UpdateLocationAreaArgument receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*UpdateLocationAreaArgument).MarshalBER, (*UpdateLocationAreaArgument).marshalBER, 3)

}
func (v *UpdateLocationAreaArgument) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	enc_subscriberid, err := v.SubscriberId.MarshalBER(ber.ChildEncodeOptions(opts, "subscriberId")...)
	if err != nil {
		return nil, qualifyBERError(err, "subscriberId", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_subscriberid)
	children = append(children, enc_subscriberid...)
	enc_previouslocareaid, err := v.PreviousLocAreaId.MarshalBER(ber.ChildEncodeOptions(opts, "previousLocAreaId")...)
	if err != nil {
		return nil, qualifyBERError(err, "previousLocAreaId", "encoding", false)
	}
	ber.RecordGeneratedBERChildPlacement(opts, len(children), enc_previouslocareaid)
	children = append(children, enc_previouslocareaid...)
	if len(v.TargetLocAreaId) < 2 || len(v.TargetLocAreaId) > 5 {
		if constraintErr := checkEncodedLength(opts, sd78d83_40, "37.4", "targetLocAreaId", "SIZE (2..5)", len(v.TargetLocAreaId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetlocareaid, encodeErr_enc_targetlocareaid := ber.EncodeOctetString([]byte(v.TargetLocAreaId))
	if encodeErr_enc_targetlocareaid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetlocareaid, "targetLocAreaId", "encoding", false)
	}
	children = append(children, enc_targetlocareaid...)
	if len(v.Cksn) < 1 || len(v.Cksn) > 1 {
		if constraintErr := checkEncodedLength(opts, sd78d83_40, "37.4", "cksn", "SIZE (1)", len(v.Cksn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cksn, encodeErr_enc_cksn := ber.EncodeOctetString([]byte(v.Cksn))
	if encodeErr_enc_cksn != nil {
		return nil, qualifyBERError(encodeErr_enc_cksn, "cksn", "encoding", false)
	}
	children = append(children, enc_cksn...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *UpdateLocationAreaArgument) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes UpdateLocationAreaArgument to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *UpdateLocationAreaArgument) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UpdateLocationAreaArgument receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_subscriberid, err := v.SubscriberId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "subscriberId", "encoding", true)
	}
	children = append(children, enc_subscriberid...)
	enc_previouslocareaid, err := v.PreviousLocAreaId.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "previousLocAreaId", "encoding", true)
	}
	children = append(children, enc_previouslocareaid...)
	if len(v.TargetLocAreaId) < 2 || len(v.TargetLocAreaId) > 5 {
		if constraintErr := checkEncodedLength(nil, sd78d83_40, "37.4", "targetLocAreaId", "SIZE (2..5)", len(v.TargetLocAreaId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_targetlocareaid, encodeErr_enc_targetlocareaid := ber.EncodeOctetString([]byte(v.TargetLocAreaId))
	if encodeErr_enc_targetlocareaid != nil {
		return nil, qualifyBERError(encodeErr_enc_targetlocareaid, "targetLocAreaId", "encoding", true)
	}
	children = append(children, enc_targetlocareaid...)
	if len(v.Cksn) < 1 || len(v.Cksn) > 1 {
		if constraintErr := checkEncodedLength(nil, sd78d83_40, "37.4", "cksn", "SIZE (1)", len(v.Cksn)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_cksn, encodeErr_enc_cksn := ber.EncodeOctetString([]byte(v.Cksn))
	if encodeErr_enc_cksn != nil {
		return nil, qualifyBERError(encodeErr_enc_cksn, "cksn", "encoding", true)
	}
	children = append(children, enc_cksn...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding UpdateLocationAreaArgument as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *UpdateLocationAreaArgument) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes UpdateLocationAreaArgument from BER/DER format.
func (destination *UpdateLocationAreaArgument) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: UpdateLocationAreaArgument destination is nil", ber.ErrInvalidValue)
	}
	v := new(UpdateLocationAreaArgument)

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
			var probe UpdateLocationAreaArgument
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_40, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = UpdateLocationAreaArgument{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*UpdateLocationAreaArgument).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding UpdateLocationAreaArgument SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "UpdateLocationAreaArgument", Cause: ber.ErrExtraData}
	}
	offset := 0
	// Decode subscriberId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field subscriberId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "subscriberId", content[offset:])
		// Decode nested CHOICE (SubscriberId)
		_, n_subscriberid, _, tlvErr_subscriberid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_subscriberid != nil {
			return qualifyBERError(tlvErr_subscriberid, "subscriberId", "decoding", false)
		}
		if offset > len(content) || n_subscriberid < 0 || n_subscriberid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.SubscriberId.UnmarshalBER(content[offset:offset+n_subscriberid], ber.ChildDecodeOptions(opts, "subscriberId")...); unmErr != nil {
			return qualifyBERError(unmErr, "subscriberId", "decoding", false)
		}
		if offset > len(content) || n_subscriberid < 0 || n_subscriberid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_subscriberid
	}
	// Decode previousLocAreaId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field previousLocAreaId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "previousLocAreaId", content[offset:])
		// Decode nested CHOICE (UpdateLocationAreaArgumentPreviousLocAreaId)
		_, n_previouslocareaid, _, tlvErr_previouslocareaid := ber.DecodeTLV(content[offset:], opts...)
		if tlvErr_previouslocareaid != nil {
			return qualifyBERError(tlvErr_previouslocareaid, "previousLocAreaId", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_previouslocareaid < 0 || n_previouslocareaid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		if unmErr := v.PreviousLocAreaId.UnmarshalBER(content[offset:offset+n_previouslocareaid], ber.ChildDecodeOptions(opts, "previousLocAreaId")...); unmErr != nil {
			return qualifyBERError(unmErr, "previousLocAreaId", "decoding", false)
		}
		if offset < 0 || offset >
			len(content) || n_previouslocareaid < 0 || n_previouslocareaid > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n_previouslocareaid
	}
	// Decode targetLocAreaId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field targetLocAreaId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "targetLocAreaId", content[offset:])
		val_targetlocareaid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "targetLocAreaId", "decoding", false)
		}
		v.TargetLocAreaId = LocAreaId(val_targetlocareaid)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.TargetLocAreaId) < 2 || len(v.TargetLocAreaId) > 5 {
			if constraintErr := checkDecodedLength(opts, sd78d83_40, "37.4", "targetLocAreaId", "SIZE (2..5)", len(v.TargetLocAreaId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode cksn
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field cksn", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "cksn", content[offset:])
		val_cksn, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "cksn", "decoding", false)
		}
		v.Cksn = CKSN(val_cksn)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.Cksn) < 1 || len(v.Cksn) > 1 {
			if constraintErr := checkDecodedLength(opts, sd78d83_40, "37.4", "cksn", "SIZE (1)", len(v.Cksn)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "UpdateLocationAreaArgument", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes CancelLocationArgumentAlternative1 to BER format.
func (v *CancelLocationArgumentAlternative1) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: CancelLocationArgumentAlternative1 receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*CancelLocationArgumentAlternative1).MarshalBER, (*CancelLocationArgumentAlternative1).marshalBER, 3)

}
func (v *CancelLocationArgumentAlternative1) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(opts, sd78d83_41, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", false)
	}
	children = append(children, enc_imsi...)
	if len(v.LMsId) < 4 || len(v.LMsId) > 4 {
		if constraintErr := checkEncodedLength(opts, sd78d83_41, "37.4", "lMsId", "SIZE (4)", len(v.LMsId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lmsid, encodeErr_enc_lmsid := ber.EncodeOctetString([]byte(v.LMsId))
	if encodeErr_enc_lmsid != nil {
		return nil, qualifyBERError(encodeErr_enc_lmsid, "lMsId", "encoding", false)
	}
	children = append(children, enc_lmsid...)
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *CancelLocationArgumentAlternative1) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes CancelLocationArgumentAlternative1 to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *CancelLocationArgumentAlternative1) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: CancelLocationArgumentAlternative1 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
		if constraintErr := checkEncodedLength(nil, sd78d83_41, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_imsi, encodeErr_enc_imsi := ber.EncodeOctetString([]byte(v.Imsi))
	if encodeErr_enc_imsi != nil {
		return nil, qualifyBERError(encodeErr_enc_imsi, "imsi", "encoding", true)
	}
	children = append(children, enc_imsi...)
	if len(v.LMsId) < 4 || len(v.LMsId) > 4 {
		if constraintErr := checkEncodedLength(nil, sd78d83_41, "37.4", "lMsId", "SIZE (4)", len(v.LMsId)); constraintErr != nil {
			return nil, constraintErr
		}
	}
	enc_lmsid, encodeErr_enc_lmsid := ber.EncodeOctetString([]byte(v.LMsId))
	if encodeErr_enc_lmsid != nil {
		return nil, qualifyBERError(encodeErr_enc_lmsid, "lMsId", "encoding", true)
	}
	children = append(children, enc_lmsid...)
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding CancelLocationArgumentAlternative1 as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *CancelLocationArgumentAlternative1) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes CancelLocationArgumentAlternative1 from BER/DER format.
func (destination *CancelLocationArgumentAlternative1) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: CancelLocationArgumentAlternative1 destination is nil", ber.ErrInvalidValue)
	}
	v := new(CancelLocationArgumentAlternative1)

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
			var probe CancelLocationArgumentAlternative1
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_41, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = CancelLocationArgumentAlternative1{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*CancelLocationArgumentAlternative1).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding CancelLocationArgumentAlternative1 SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "CancelLocationArgumentAlternative1", Cause: ber.ErrExtraData}
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
		if len(v.Imsi) < 2 || len(v.Imsi) > 8 {
			if constraintErr := checkDecodedLength(opts, sd78d83_41, "37.4", "imsi", "SIZE (2..8)", len(v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	// Decode lMsId
	if offset >= len(content) {
		return fmt.Errorf("%w: missing required field lMsId", ber.ErrUnexpectedElement)
	}
	{
		ber.MarkPreflightTarget(opts, "lMsId", content[offset:])
		val_lmsid, n, err := ber.DecodeOctetString(content[offset:], opts...)
		if err != nil {
			return qualifyBERError(err, "lMsId", "decoding", false)
		}
		v.LMsId = LMsId(val_lmsid)
		if offset < 0 || offset >
			len(content) || n < 0 || n > len(content[offset:]) {
			return fmt.Errorf("invalid BER content window")
		}

		offset += n
		if len(v.LMsId) < 4 || len(v.LMsId) > 4 {
			if constraintErr := checkDecodedLength(opts, sd78d83_41, "37.4", "lMsId", "SIZE (4)", len(v.LMsId)); constraintErr != nil {
				return constraintErr
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "CancelLocationArgumentAlternative1", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SearchForMobileSubscriberArgumentStoredLocationArea to BER format.
func (v *SearchForMobileSubscriberArgumentStoredLocationArea) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SearchForMobileSubscriberArgumentStoredLocationArea receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SearchForMobileSubscriberArgumentStoredLocationArea).MarshalBER, (*SearchForMobileSubscriberArgumentStoredLocationArea).marshalBER, 3)

}
func (v *SearchForMobileSubscriberArgumentStoredLocationArea) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SearchForMobileSubscriberArgumentStoredLocationArea) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative0:
		if v.Alternative0 == nil {
			return nil, fmt.Errorf("%w: choice SearchForMobileSubscriberArgumentStoredLocationArea: alternative0 is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Alternative0))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "alternative0", "encoding", false)
		}
		if len(*v.Alternative0) < 2 || len(*v.Alternative0) > 5 {
			if constraintErr := checkEncodedLength(opts, "MAP-Operations.SearchForMobileSubscriber-argument-storedLocationArea", "37.4", "alternative0", "SIZE (2..5)", len(*v.Alternative0)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative1:
		enc_1 := ber.EncodeNull()
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SearchForMobileSubscriberArgumentStoredLocationArea", v.Choice)
	}
}

// MarshalDER encodes SearchForMobileSubscriberArgumentStoredLocationArea to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SearchForMobileSubscriberArgumentStoredLocationArea) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SearchForMobileSubscriberArgumentStoredLocationArea receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative0:
			return nil, qualifyBERError(err, "alternative0", "encoding", true)
		case SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative1:
			return nil, qualifyBERError(err, "alternative1", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SearchForMobileSubscriberArgumentStoredLocationArea as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SearchForMobileSubscriberArgumentStoredLocationArea) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SearchForMobileSubscriberArgumentStoredLocationArea from BER/DER format.
func (destination *SearchForMobileSubscriberArgumentStoredLocationArea) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SearchForMobileSubscriberArgumentStoredLocationArea destination is nil", ber.ErrInvalidValue)
	}
	v := new(SearchForMobileSubscriberArgumentStoredLocationArea)

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
				opts, v, &v.berReplayNode_, (*SearchForMobileSubscriberArgumentStoredLocationArea).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SearchForMobileSubscriberArgumentStoredLocationArea
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-Operations.SearchForMobileSubscriber-argument-storedLocationArea", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SearchForMobileSubscriberArgumentStoredLocationArea{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SearchForMobileSubscriberArgumentStoredLocationArea CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SearchForMobileSubscriberArgumentStoredLocationArea: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SearchForMobileSubscriberArgumentStoredLocationArea CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SearchForMobileSubscriberArgumentStoredLocationArea", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SearchForMobileSubscriberArgumentStoredLocationArea.alternative1", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative0
		ber.MarkPreflightTarget(opts, "alternative0", choiceData)
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return qualifyBERError(osErr, "alternative0", "decoding", false)
		}
		tmp := LocAreaId(decVal)
		v.Alternative0 = &tmp
		if len(*v.Alternative0) < 2 || len(*v.Alternative0) > 5 {
			if constraintErr := checkDecodedLength(opts, "MAP-Operations.SearchForMobileSubscriber-argument-storedLocationArea", "37.4", "alternative0", "SIZE (2..5)", len(*v.Alternative0)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = SearchForMobileSubscriberArgumentStoredLocationAreaChoiceAlternative1
		ber.MarkPreflightTarget(opts, "alternative1", choiceData)
		_, nullErr := ber.DecodeNull(choiceData, opts...)
		if nullErr != nil {
			return qualifyBERError(nullErr, "alternative1", "decoding", false)
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for SearchForMobileSubscriberArgumentStoredLocationArea CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes SendInfoForIncomingCallArgumentIncomingId to BER format.
func (v *SendInfoForIncomingCallArgumentIncomingId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendInfoForIncomingCallArgumentIncomingId receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendInfoForIncomingCallArgumentIncomingId).MarshalBER, (*SendInfoForIncomingCallArgumentIncomingId).marshalBER, 3)

}
func (v *SendInfoForIncomingCallArgumentIncomingId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SendInfoForIncomingCallArgumentIncomingId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SendInfoForIncomingCallArgumentIncomingIdChoiceRoamingNumber:
		if v.RoamingNumber == nil {
			return nil, fmt.Errorf("%w: choice SendInfoForIncomingCallArgumentIncomingId: roamingNumber is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.RoamingNumber))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "roamingNumber", "encoding", false)
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_42, "37.4", "roamingNumber", "SIZE (1..10)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_42, "37.4", "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "roamingNumber", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SendInfoForIncomingCallArgumentIncomingIdChoiceImsi:
		if v.Imsi == nil {
			return nil, fmt.Errorf("%w: choice SendInfoForIncomingCallArgumentIncomingId: imsi is nil", ber.ErrInvalidValue)
		}
		enc_1, encodeErr_enc_1 := ber.EncodeOctetString([]byte(*v.Imsi))
		if encodeErr_enc_1 != nil {
			return nil, qualifyBERError(encodeErr_enc_1, "imsi", "encoding", false)
		}
		if len(*v.Imsi) < 2 || len(*v.Imsi) > 8 {
			if constraintErr := checkEncodedLength(opts, sd78d83_42, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "imsi", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SendInfoForIncomingCallArgumentIncomingId", v.Choice)
	}
}

// MarshalDER encodes SendInfoForIncomingCallArgumentIncomingId to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendInfoForIncomingCallArgumentIncomingId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendInfoForIncomingCallArgumentIncomingId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case SendInfoForIncomingCallArgumentIncomingIdChoiceRoamingNumber:
			return nil, qualifyBERError(err, "roamingNumber", "encoding", true)
		case SendInfoForIncomingCallArgumentIncomingIdChoiceImsi:
			return nil, qualifyBERError(err, "imsi", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SendInfoForIncomingCallArgumentIncomingId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SendInfoForIncomingCallArgumentIncomingId) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendInfoForIncomingCallArgumentIncomingId from BER/DER format.
func (destination *SendInfoForIncomingCallArgumentIncomingId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendInfoForIncomingCallArgumentIncomingId destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendInfoForIncomingCallArgumentIncomingId)

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
				opts, v, &v.berReplayNode_, (*SendInfoForIncomingCallArgumentIncomingId).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SendInfoForIncomingCallArgumentIncomingId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_42, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendInfoForIncomingCallArgumentIncomingId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SendInfoForIncomingCallArgumentIncomingId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SendInfoForIncomingCallArgumentIncomingId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SendInfoForIncomingCallArgumentIncomingId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SendInfoForIncomingCallArgumentIncomingId", Cause: ber.ErrExtraData}
	}

	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 {
		v.Choice = SendInfoForIncomingCallArgumentIncomingIdChoiceRoamingNumber
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
			if constraintErr := checkDecodedLength(opts, sd78d83_42, "37.4", "roamingNumber", "SIZE (1..10)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_42, "37.4", "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 {
		v.Choice = SendInfoForIncomingCallArgumentIncomingIdChoiceImsi
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
			if constraintErr := checkDecodedLength(opts, sd78d83_42, "37.4", "imsi", "SIZE (2..8)", len(*v.Imsi)); constraintErr != nil {
				return constraintErr
			}
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for SendInfoForIncomingCallArgumentIncomingId CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes SendRoutingInfoForSMResultComponent1 to BER format.
func (v *SendRoutingInfoForSMResultComponent1) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoForSMResultComponent1 receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendRoutingInfoForSMResultComponent1).MarshalBER, (*SendRoutingInfoForSMResultComponent1).marshalBER, 3)

}
func (v *SendRoutingInfoForSMResultComponent1) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SendRoutingInfoForSMResultComponent1) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SendRoutingInfoForSMResultComponent1ChoiceAlternative0:
		if v.Alternative0 == nil {
			return nil, fmt.Errorf("%w: choice SendRoutingInfoForSMResultComponent1: alternative0 is nil", ber.ErrInvalidValue)
		}
		enc_0, err := v.Alternative0.MarshalBER(ber.ChildEncodeOptions(opts, "alternative0")...)
		if err != nil {
			return nil, qualifyBERError(err, "alternative0", "encoding", false)
		}
		retagged_enc_0, tagErr_enc_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_0)
		if tagErr_enc_0 != nil {
			return nil, qualifyBERError(tagErr_enc_0, "alternative0", "encoding", false)
		}
		enc_0 = retagged_enc_0
		return enc_0, nil
	case SendRoutingInfoForSMResultComponent1ChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("%w: choice SendRoutingInfoForSMResultComponent1: forwardingData is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ForwardingData.MarshalBER(ber.ChildEncodeOptions(opts, "forwardingData")...)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingData", "encoding", false)
		}
		retagged_enc_1, tagErr_enc_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_1)
		if tagErr_enc_1 != nil {
			return nil, qualifyBERError(tagErr_enc_1, "forwardingData", "encoding", false)
		}
		enc_1 = retagged_enc_1
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SendRoutingInfoForSMResultComponent1", v.Choice)
	}
}

// MarshalDER encodes SendRoutingInfoForSMResultComponent1 to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendRoutingInfoForSMResultComponent1) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoForSMResultComponent1 receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SendRoutingInfoForSMResultComponent1ChoiceAlternative0:
		if v.Alternative0 == nil {
			return nil, fmt.Errorf("%w: choice SendRoutingInfoForSMResultComponent1: alternative0 is nil", ber.ErrInvalidValue)
		}
		enc_der_0, err := v.Alternative0.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "alternative0", "encoding", true)
		}
		retagged_enc_der_0, tagErr_enc_der_0 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 0, enc_der_0)
		if tagErr_enc_der_0 != nil {
			return nil, qualifyBERError(tagErr_enc_der_0, "alternative0", "encoding", true)
		}
		enc_der_0 = retagged_enc_der_0
		if derErr := ber.ValidateDEREncodedElement(enc_der_0); derErr != nil {
			return nil, qualifyBERError(derErr, "alternative0", "encoding", true)
		}
		return enc_der_0, nil
	case SendRoutingInfoForSMResultComponent1ChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("%w: choice SendRoutingInfoForSMResultComponent1: forwardingData is nil", ber.ErrInvalidValue)
		}
		enc_der_1, err := v.ForwardingData.MarshalDER()
		if err != nil {
			return nil, qualifyBERError(err, "forwardingData", "encoding", true)
		}
		retagged_enc_der_1, tagErr_enc_der_1 := ber.EncodeImplicitTagWithClass(tag.ClassContextSpecific, 1, enc_der_1)
		if tagErr_enc_der_1 != nil {
			return nil, qualifyBERError(tagErr_enc_der_1, "forwardingData", "encoding", true)
		}
		enc_der_1 = retagged_enc_der_1
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
		case SendRoutingInfoForSMResultComponent1ChoiceAlternative0:
			return nil, qualifyBERError(err, "alternative0", "encoding", true)
		case SendRoutingInfoForSMResultComponent1ChoiceForwardingData:
			return nil, qualifyBERError(err, "forwardingData", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SendRoutingInfoForSMResultComponent1 as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SendRoutingInfoForSMResultComponent1) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendRoutingInfoForSMResultComponent1 from BER/DER format.
func (destination *SendRoutingInfoForSMResultComponent1) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendRoutingInfoForSMResultComponent1 destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendRoutingInfoForSMResultComponent1)

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
				opts, v, &v.berReplayNode_, (*SendRoutingInfoForSMResultComponent1).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SendRoutingInfoForSMResultComponent1
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-Operations.SendRoutingInfoForSM-result-component1", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendRoutingInfoForSMResultComponent1{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SendRoutingInfoForSMResultComponent1 CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SendRoutingInfoForSMResultComponent1: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInfoForSMResultComponent1 CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInfoForSMResultComponent1", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SendRoutingInfoForSMResultComponent1.alternative0", "decoding", false)
	}
	if (peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SendRoutingInfoForSMResultComponent1.forwardingData", "decoding", false)
	}
	if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 0 && peekTag.Constructed == true {
		v.Choice = SendRoutingInfoForSMResultComponent1ChoiceAlternative0
		ber.MarkPreflightTarget(opts, "alternative0", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "alternative0", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec SendRoutingInfoForSMResultComponent1Alternative0
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "alternative0")...); unmErr != nil {
			return qualifyBERError(unmErr, "alternative0", "decoding", false)
		}
		v.Alternative0 = &dec
	} else if peekTag.Class == tag.ClassContextSpecific && peekTag.Number == 1 && peekTag.Constructed == true {
		v.Choice = SendRoutingInfoForSMResultComponent1ChoiceForwardingData
		ber.MarkPreflightTarget(opts, "forwardingData", choiceData)
		_, _, rawVal, tlvErr := ber.DecodeTLV(choiceData, opts...)
		if tlvErr != nil {
			return qualifyBERError(tlvErr, "forwardingData", "decoding", false)
		}
		_ = rawVal
		reconstructed, reconstructionErr := ber.EncodeImplicitTagWithClass(tag.ClassUniversal, tag.TagSequence, choiceData)
		if reconstructionErr != nil {
			return reconstructionErr
		}
		var dec ForwardingData
		if unmErr := dec.UnmarshalBER(reconstructed, ber.ChildDecodeOptions(opts, "forwardingData")...); unmErr != nil {
			return qualifyBERError(unmErr, "forwardingData", "decoding", false)
		}
		v.ForwardingData = &dec
	} else {
		return fmt.Errorf("%w: unknown tag %s for SendRoutingInfoForSMResultComponent1 CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes SendRoutingInfoForSMResultComponent1Alternative0 to BER format.
func (v *SendRoutingInfoForSMResultComponent1Alternative0) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoForSMResultComponent1Alternative0 receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendRoutingInfoForSMResultComponent1Alternative0).MarshalBER, (*SendRoutingInfoForSMResultComponent1Alternative0).marshalBER, 3)

}
func (v *SendRoutingInfoForSMResultComponent1Alternative0) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
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
	if v.LMsId != nil {
		if len(*v.LMsId) < 4 || len(*v.LMsId) > 4 {
			if constraintErr := checkEncodedLength(opts, sd78d83_43, "37.4", "lMsId", "SIZE (4)", len(*v.LMsId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsid, encodeErr_enc_lmsid := ber.EncodeOctetString([]byte(*v.LMsId))
		if encodeErr_enc_lmsid != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsid, "lMsId", "encoding", false)
		}
		children = append(children, enc_lmsid...)
	}
	ber.RecordGeneratedBERContainer(opts, children)
	return ber.EncodeSequence(children)
}
func (v *SendRoutingInfoForSMResultComponent1Alternative0) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// MarshalDER encodes SendRoutingInfoForSMResultComponent1Alternative0 to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendRoutingInfoForSMResultComponent1Alternative0) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInfoForSMResultComponent1Alternative0 receiver is nil", ber.ErrInvalidValue)
	}
	var children []byte
	enc_locationinfo, err := v.LocationInfo.MarshalDER()
	if err != nil {
		return nil, qualifyBERError(err, "locationInfo", "encoding", true)
	}
	children = append(children, enc_locationinfo...)
	if v.LMsId != nil {
		if len(*v.LMsId) < 4 || len(*v.LMsId) > 4 {
			if constraintErr := checkEncodedLength(nil, sd78d83_43, "37.4", "lMsId", "SIZE (4)", len(*v.LMsId)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		enc_lmsid, encodeErr_enc_lmsid := ber.EncodeOctetString([]byte(*v.LMsId))
		if encodeErr_enc_lmsid != nil {
			return nil, qualifyBERError(encodeErr_enc_lmsid, "lMsId", "encoding", true)
		}
		children = append(children, enc_lmsid...)
	}
	encoded, setErr := ber.EncodeSequence(children)
	if setErr != nil {
		return nil, setErr
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		return nil, fmt.Errorf("%s: %w", "encoding SendRoutingInfoForSMResultComponent1Alternative0 as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}
func (v *SendRoutingInfoForSMResultComponent1Alternative0) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendRoutingInfoForSMResultComponent1Alternative0 from BER/DER format.
func (destination *SendRoutingInfoForSMResultComponent1Alternative0) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendRoutingInfoForSMResultComponent1Alternative0 destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendRoutingInfoForSMResultComponent1Alternative0)

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
			var probe SendRoutingInfoForSMResultComponent1Alternative0
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_43, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendRoutingInfoForSMResultComponent1Alternative0{}
	defer func() {
		if returnErr == nil {
			returnErr = completeValueBER(data,
				opts, v, &v.berReplayNode_, (*SendRoutingInfoForSMResultComponent1Alternative0).MarshalBER)
		}

	}()
	content, total, err := ber.DecodeSequenceContent(data, opts...)
	if err != nil {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInfoForSMResultComponent1Alternative0 SEQUENCE", qualifyBERError(err, "", "decoding", false))
	}
	if total != len(data) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInfoForSMResultComponent1Alternative0", Cause: ber.ErrExtraData}
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
	// Decode lMsId
	if offset < len(content) {
		peekTag, peekErr := ber.PeekTag(content[offset:])
		if peekErr == nil {
			if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
				ber.MarkPreflightTarget(opts, "lMsId", content[offset:])
				val_lmsid, n, err := ber.DecodeOctetString(content[offset:], opts...)
				if err != nil {
					return qualifyBERError(err, "lMsId", "decoding", false)
				}
				tmp_lmsid := LMsId(val_lmsid)
				v.LMsId = &tmp_lmsid
				if offset < 0 || offset >
					len(content) || n < 0 || n > len(content[offset:]) {
					return fmt.Errorf("invalid BER content window")
				}

				offset += n
				if len(*v.LMsId) < 4 || len(*v.LMsId) > 4 {
					if constraintErr := checkDecodedLength(opts, sd78d83_43, "37.4", "lMsId", "SIZE (4)", len(*v.LMsId)); constraintErr != nil {
						return constraintErr
					}
				}
			}
		}
	}
	if offset != len(content) {
		return &ber.DecodeError{Offset: offset, TypeName: "SendRoutingInfoForSMResultComponent1Alternative0", Cause: ber.ErrUnexpectedElement}
	}
	return nil
}

// MarshalBER encodes SendRoutingInformationResultRoutingInfo to BER format.
func (v *SendRoutingInformationResultRoutingInfo) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInformationResultRoutingInfo receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*SendRoutingInformationResultRoutingInfo).MarshalBER, (*SendRoutingInformationResultRoutingInfo).marshalBER, 3)

}
func (v *SendRoutingInformationResultRoutingInfo) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *SendRoutingInformationResultRoutingInfo) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case SendRoutingInformationResultRoutingInfoChoiceRoamingNumber:
		if v.RoamingNumber == nil {
			return nil, fmt.Errorf("%w: choice SendRoutingInformationResultRoutingInfo: roamingNumber is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.RoamingNumber))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "roamingNumber", "encoding", false)
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 10 {
			if constraintErr := checkEncodedLength(opts, sd78d83_44, "37.4", "roamingNumber", "SIZE (1..10)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := checkEncodedLength(opts, sd78d83_44, "37.4", "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case SendRoutingInformationResultRoutingInfoChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("%w: choice SendRoutingInformationResultRoutingInfo: forwardingData is nil", ber.ErrInvalidValue)
		}
		enc_1, err := v.ForwardingData.MarshalBER(ber.ChildEncodeOptions(opts, "forwardingData")...)
		if err != nil {
			return nil, qualifyBERError(err, "forwardingData", "encoding", false)
		}
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for SendRoutingInformationResultRoutingInfo", v.Choice)
	}
}

// MarshalDER encodes SendRoutingInformationResultRoutingInfo to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *SendRoutingInformationResultRoutingInfo) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: SendRoutingInformationResultRoutingInfo receiver is nil", ber.ErrInvalidValue)
	}
	switch v.Choice {
	case SendRoutingInformationResultRoutingInfoChoiceForwardingData:
		if v.ForwardingData == nil {
			return nil, fmt.Errorf("%w: choice SendRoutingInformationResultRoutingInfo: forwardingData is nil", ber.ErrInvalidValue)
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
		case SendRoutingInformationResultRoutingInfoChoiceRoamingNumber:
			return nil, qualifyBERError(err, "roamingNumber", "encoding", true)
		case SendRoutingInformationResultRoutingInfoChoiceForwardingData:
			return nil, qualifyBERError(err, "forwardingData", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding SendRoutingInformationResultRoutingInfo as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *SendRoutingInformationResultRoutingInfo) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes SendRoutingInformationResultRoutingInfo from BER/DER format.
func (destination *SendRoutingInformationResultRoutingInfo) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: SendRoutingInformationResultRoutingInfo destination is nil", ber.ErrInvalidValue)
	}
	v := new(SendRoutingInformationResultRoutingInfo)

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
				opts, v, &v.berReplayNode_, (*SendRoutingInformationResultRoutingInfo).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe SendRoutingInformationResultRoutingInfo
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, sd78d83_44, opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = SendRoutingInformationResultRoutingInfo{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for SendRoutingInformationResultRoutingInfo CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for SendRoutingInformationResultRoutingInfo: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding SendRoutingInformationResultRoutingInfo CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "SendRoutingInformationResultRoutingInfo", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 16) && peekTag.Constructed != true {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "SendRoutingInformationResultRoutingInfo.forwardingData", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = SendRoutingInformationResultRoutingInfoChoiceRoamingNumber
		ber.MarkPreflightTarget(opts, "roamingNumber", choiceData)
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return qualifyBERError(osErr, "roamingNumber", "decoding", false)
		}
		tmp := IsdnAddressString(decVal)
		v.RoamingNumber = &tmp
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 10 {
			if constraintErr := checkDecodedLength(opts, sd78d83_44, "37.4", "roamingNumber", "SIZE (1..10)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
		if len(*v.RoamingNumber) < 1 || len(*v.RoamingNumber) > 20 {
			if constraintErr := checkDecodedLength(opts, sd78d83_44, "37.4", "roamingNumber", "SIZE (1..20)", len(*v.RoamingNumber)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 16 && peekTag.Constructed == true {
		v.Choice = SendRoutingInformationResultRoutingInfoChoiceForwardingData
		ber.MarkPreflightTarget(opts, "forwardingData", choiceData)
		var dec ForwardingData
		if unmErr := dec.UnmarshalBER(choiceData, ber.ChildDecodeOptions(opts, "forwardingData")...); unmErr != nil {
			return qualifyBERError(unmErr, "forwardingData", "decoding", false)
		}
		v.ForwardingData = &dec
	} else {
		return fmt.Errorf("%w: unknown tag %s for SendRoutingInformationResultRoutingInfo CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

// MarshalBER encodes UpdateLocationAreaArgumentPreviousLocAreaId to BER format.
func (v *UpdateLocationAreaArgumentPreviousLocAreaId) MarshalBER(opts ...ber.EncodeOption) (returnBytes []byte, returnErr error) {

	if v == nil {
		return nil, fmt.Errorf("%w: UpdateLocationAreaArgumentPreviousLocAreaId receiver is nil", ber.ErrInvalidValue)
	}
	return marshalFramedValue(v, v.berReplayNode_, opts, (*UpdateLocationAreaArgumentPreviousLocAreaId).MarshalBER, (*UpdateLocationAreaArgumentPreviousLocAreaId).marshalBER, 3)

}
func (v *UpdateLocationAreaArgumentPreviousLocAreaId) appendBERLinear(encoder *ber.LinearEncoder, opts ...ber.EncodeOption) ([]byte, error) {
	encoded, err := v.MarshalBER(opts...)
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}
func (v *UpdateLocationAreaArgumentPreviousLocAreaId) marshalBER(opts ...ber.EncodeOption) ([]byte, error) {
	if err := ber.ValidateEncodeOptions(opts...); err != nil {
		return nil, err
	}
	switch v.Choice {
	case UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative0:
		if v.Alternative0 == nil {
			return nil, fmt.Errorf("%w: choice UpdateLocationAreaArgumentPreviousLocAreaId: alternative0 is nil", ber.ErrInvalidValue)
		}
		enc_0, encodeErr_enc_0 := ber.EncodeOctetString([]byte(*v.Alternative0))
		if encodeErr_enc_0 != nil {
			return nil, qualifyBERError(encodeErr_enc_0, "alternative0", "encoding", false)
		}
		if len(*v.Alternative0) < 2 || len(*v.Alternative0) > 5 {
			if constraintErr := checkEncodedLength(opts, "MAP-Operations.UpdateLocationArea-argument-previousLocAreaId", "37.4", "alternative0", "SIZE (2..5)", len(*v.Alternative0)); constraintErr != nil {
				return nil, constraintErr
			}
		}
		return enc_0, nil
	case UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative1:
		enc_1 := ber.EncodeNull()
		return enc_1, nil
	default:
		return nil, fmt.Errorf("unknown choice %d for UpdateLocationAreaArgumentPreviousLocAreaId", v.Choice)
	}
}

// MarshalDER encodes UpdateLocationAreaArgumentPreviousLocAreaId to DER format.
// Opaque descendants pass generic DER checks; foreign schema rules need a typed binding.
func (v *UpdateLocationAreaArgumentPreviousLocAreaId) MarshalDER() ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("%w: UpdateLocationAreaArgumentPreviousLocAreaId receiver is nil", ber.ErrInvalidValue)
	}
	encoded, err := v.marshalBER()
	if err != nil {
		return nil, err
	}
	if err := ber.ValidateDEREncodedElement(encoded); err != nil {
		switch v.Choice {
		case UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative0:
			return nil, qualifyBERError(err, "alternative0", "encoding", true)
		case UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative1:
			return nil, qualifyBERError(err, "alternative1", "encoding", true)
		}
		return nil, fmt.Errorf("%s: %w", "encoding UpdateLocationAreaArgumentPreviousLocAreaId as DER", qualifyBERError(err, "", "encoding", true))
	}
	return encoded, nil
}

func (v *UpdateLocationAreaArgumentPreviousLocAreaId) appendDERLinear(encoder *ber.LinearEncoder) ([]byte, error) {
	encoded, err := v.MarshalDER()
	if err != nil {
		return nil, err
	}
	encoder.Append(encoded)
	return nil, nil
}

// UnmarshalBER decodes UpdateLocationAreaArgumentPreviousLocAreaId from BER/DER format.
func (destination *UpdateLocationAreaArgumentPreviousLocAreaId) UnmarshalBER(data []byte, opts ...ber.DecodeOption) (returnErr error) {
	if destination == nil {
		return fmt.Errorf("%w: UpdateLocationAreaArgumentPreviousLocAreaId destination is nil", ber.ErrInvalidValue)
	}
	v := new(UpdateLocationAreaArgumentPreviousLocAreaId)

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
				opts, v, &v.berReplayNode_, (*UpdateLocationAreaArgumentPreviousLocAreaId).MarshalBER)
		}

	}()
	preparedData, preparedOptions, prepareErr := ber.PrepareGeneratedBERInput(data, opts)
	if prepareErr != nil {
		return ber.DiagnosePreflight(prepareErr, data, opts, "child", func(probeOpts []ber.DecodeOption) error {
			var probe UpdateLocationAreaArgumentPreviousLocAreaId
			return probe.UnmarshalBER(data, probeOpts...)
		})
	}
	data, opts = preparedData, preparedOptions
	opts = ber.LocateDecodedElement(data, "MAP-Operations.UpdateLocationArea-argument-previousLocAreaId", opts)
	defer func() { returnErr = ber.LocateDecodeError(returnErr, opts) }()
	*v = UpdateLocationAreaArgumentPreviousLocAreaId{}
	if len(data) == 0 {
		return fmt.Errorf("empty data for UpdateLocationAreaArgumentPreviousLocAreaId CHOICE")
	}
	choiceData := data
	peekTag, peekErr := ber.PeekTag(choiceData)
	if peekErr != nil {
		return fmt.Errorf("peeking tag for UpdateLocationAreaArgumentPreviousLocAreaId: %w", peekErr)
	}

	_, total, _, tlvErr := ber.DecodeTLV(choiceData, opts...)
	if tlvErr != nil {
		return fmt.Errorf("%s: %w", "decoding UpdateLocationAreaArgumentPreviousLocAreaId CHOICE", qualifyBERError(tlvErr, "", "decoding", false))
	}
	if total != len(choiceData) {
		return &ber.DecodeError{Offset: total, TypeName: "UpdateLocationAreaArgumentPreviousLocAreaId", Cause: ber.ErrExtraData}
	}

	if (peekTag.Class == tag.ClassUniversal && peekTag.Number == 5) && peekTag.Constructed != false {
		return qualifyBERError(fmt.Errorf("%w: invalid primitive/constructed form for tag %s", ber.ErrInvalidTag, peekTag), "UpdateLocationAreaArgumentPreviousLocAreaId.alternative1", "decoding", false)
	}
	if peekTag.Class == tag.ClassUniversal && peekTag.Number == 4 {
		v.Choice = UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative0
		ber.MarkPreflightTarget(opts, "alternative0", choiceData)
		decVal, _, osErr := ber.DecodeOctetString(choiceData, opts...)
		if osErr != nil {
			return qualifyBERError(osErr, "alternative0", "decoding", false)
		}
		tmp := LocAreaId(decVal)
		v.Alternative0 = &tmp
		if len(*v.Alternative0) < 2 || len(*v.Alternative0) > 5 {
			if constraintErr := checkDecodedLength(opts, "MAP-Operations.UpdateLocationArea-argument-previousLocAreaId", "37.4", "alternative0", "SIZE (2..5)", len(*v.Alternative0)); constraintErr != nil {
				return constraintErr
			}
		}
	} else if peekTag.Class == tag.ClassUniversal && peekTag.Number == 5 && peekTag.Constructed == false {
		v.Choice = UpdateLocationAreaArgumentPreviousLocAreaIdChoiceAlternative1
		ber.MarkPreflightTarget(opts, "alternative1", choiceData)
		_, nullErr := ber.DecodeNull(choiceData, opts...)
		if nullErr != nil {
			return qualifyBERError(nullErr, "alternative1", "decoding", false)
		}
	} else {
		return fmt.Errorf("%w: unknown tag %s for UpdateLocationAreaArgumentPreviousLocAreaId CHOICE", ber.ErrUnexpectedElement, peekTag)
	}
	return nil
}

const (
	sd78d83_0  = "MAP-Operations.ActivateSS-argument"
	sd78d83_1  = "MAP-Operations.ActivateTraceMode-argument"
	sd78d83_2  = "MAP-Operations.AlertServiceCentre-argument"
	sd78d83_3  = "MAP-Operations.Authenticate-argument"
	sd78d83_4  = "MAP-Operations.BeginSubscriberActivity-argument"
	sd78d83_5  = "MAP-Operations.CompleteCall-argument"
	sd78d83_6  = "MAP-Operations.ConnectToFollowingAddress-argument"
	sd78d83_7  = "MAP-Operations.DeactivateSS-argument"
	sd78d83_8  = "MAP-Operations.DeactivateTraceMode-argument"
	sd78d83_9  = "MAP-Operations.DeleteSubscriberData-argument"
	sd78d83_10 = "MAP-Operations.EraseSS-argument"
	sd78d83_11 = "MAP-Operations.ForwardShortMessage-argument"
	sd78d83_12 = "MAP-Operations.ForwardSsNotification-argument"
	sd78d83_13 = "MAP-Operations.InsertSubscriberData-argument"
	sd78d83_14 = "MAP-Operations.InterrogateSS-argument"
	sd78d83_15 = "MAP-Operations.InterrogateSS-result"
	sd78d83_16 = "MAP-Operations.InvokeSS-argument"
	sd78d83_17 = "MAP-Operations.NoteInternalHandover-argument"
	sd78d83_18 = "MAP-Operations.Page-argument"
	sd78d83_19 = "MAP-Operations.PerformHandover-argument"
	sd78d83_20 = "MAP-Operations.PerformHandover-result"
	sd78d83_21 = "MAP-Operations.PerformSubsequentHandover-argument"
	sd78d83_22 = "MAP-Operations.ProcessAccessRequest-argument"
	sd78d83_23 = "MAP-Operations.ProcessAccessRequest-result"
	sd78d83_24 = "MAP-Operations.ProvideRoamingNumber-argument"
	sd78d83_25 = "MAP-Operations.RegisterChargingInformation-argument"
	sd78d83_26 = "MAP-Operations.RegisterSS-argument"
	sd78d83_27 = "MAP-Operations.Reset-argument"
	sd78d83_28 = "MAP-Operations.SearchForMobileSubscriber-argument"
	sd78d83_29 = "MAP-Operations.SendInfoForIncomingCall-argument"
	sd78d83_30 = "MAP-Operations.SendInfoForOutgoingCall-argument"
	sd78d83_31 = "MAP-Operations.SendParameters-argument"
	sd78d83_32 = "MAP-Operations.SendRoutingInfoForSM-argument"
	sd78d83_33 = "MAP-Operations.SendRoutingInfoForSM-result"
	sd78d83_34 = "MAP-Operations.SendRoutingInformation-argument"
	sd78d83_35 = "MAP-Operations.SendRoutingInformation-result"
	sd78d83_36 = "MAP-Operations.SetCipheringMode-argument"
	sd78d83_37 = "MAP-Operations.SetMessageWaitingData-argument"
	sd78d83_38 = "MAP-Operations.TraceSubscriberActivity-argument"
	sd78d83_39 = "MAP-Operations.UpdateLocation-argument"
	sd78d83_40 = "MAP-Operations.UpdateLocationArea-argument"
	sd78d83_41 = "MAP-Operations.CancelLocation-argument-alternative1"
	sd78d83_42 = "MAP-Operations.SendInfoForIncomingCall-argument-incomingId"
	sd78d83_43 = "MAP-Operations.SendRoutingInfoForSM-result-component1-alternative0"
	sd78d83_44 = "MAP-Operations.SendRoutingInformation-result-routingInfo"
)
