// Code generated from the edition's declared type inventory. DO NOT EDIT.
package gsm0902_v3_11_0

import (
	"reflect"
	"testing"
)

func TestEditionAllDeclaredTypesExposeTypedParts(t *testing.T) {
	for _, row := range []struct {
		name string
		typ  reflect.Type
	}{
		{"MAP-AbortInformation.MAPAbortInformation", reflect.TypeFor[MAPAbortInformation]()},
		{"MAP-DataTypes.TBCD-STRING", reflect.TypeFor[TBCDSTRING]()},
		{"MAP-DataTypes.AddressString", reflect.TypeFor[AddressString]()},
		{"MAP-DataTypes.IsdnAddressString", reflect.TypeFor[IsdnAddressString]()},
		{"MAP-DataTypes.ExternalSignalInfo", reflect.TypeFor[ExternalSignalInfo]()},
		{"MAP-DataTypes.SignalInfo", reflect.TypeFor[SignalInfo]()},
		{"MAP-DataTypes.ProtocolId", reflect.TypeFor[ProtocolId]()},
		{"MAP-DataTypes.IMSI", reflect.TypeFor[IMSI]()},
		{"MAP-DataTypes.TMSI", reflect.TypeFor[TMSI]()},
		{"MAP-DataTypes.SubscriberId", reflect.TypeFor[SubscriberId]()},
		{"MAP-DataTypes.IMEI", reflect.TypeFor[IMEI]()},
		{"MAP-DataTypes.LocAreaId", reflect.TypeFor[LocAreaId]()},
		{"MAP-DataTypes.LocationInfo", reflect.TypeFor[LocationInfo]()},
		{"MAP-DataTypes.HlrId", reflect.TypeFor[HlrId]()},
		{"MAP-DataTypes.HlrList", reflect.TypeFor[HlrList]()},
		{"MAP-DataTypes.LMsId", reflect.TypeFor[LMsId]()},
		{"MAP-DataTypes.GlobalCellId", reflect.TypeFor[GlobalCellId]()},
		{"MAP-DataTypes.Category", reflect.TypeFor[Category]()},
		{"MAP-DataTypes.EquipStatus", reflect.TypeFor[EquipStatus]()},
		{"MAP-DataTypes.BearerServiceCode", reflect.TypeFor[BearerServiceCode]()},
		{"MAP-DataTypes.BearerServiceList", reflect.TypeFor[BearerServiceList]()},
		{"MAP-DataTypes.TeleserviceCode", reflect.TypeFor[TeleserviceCode]()},
		{"MAP-DataTypes.TeleserviceList", reflect.TypeFor[TeleserviceList]()},
		{"MAP-DataTypes.BasicServiceCode", reflect.TypeFor[BasicServiceCode]()},
		{"MAP-DataTypes.BasicServiceList", reflect.TypeFor[BasicServiceList]()},
		{"MAP-DataTypes.SubscriberStatus", reflect.TypeFor[SubscriberStatus]()},
		{"MAP-DataTypes.SS-Code", reflect.TypeFor[SSCode]()},
		{"MAP-DataTypes.SS-CodeList", reflect.TypeFor[SSCodeList]()},
		{"MAP-DataTypes.SS-Status", reflect.TypeFor[SSStatus]()},
		{"MAP-DataTypes.SS-Information", reflect.TypeFor[SSInformation]()},
		{"MAP-DataTypes.SS-InfoList", reflect.TypeFor[SSInfoList]()},
		{"MAP-DataTypes.SS-Data", reflect.TypeFor[SSData]()},
		{"MAP-DataTypes.SS-DataList", reflect.TypeFor[SSDataList]()},
		{"MAP-DataTypes.SS-Request", reflect.TypeFor[SSRequest]()},
		{"MAP-DataTypes.SS-SubscriptionOption", reflect.TypeFor[SSSubscriptionOption]()},
		{"MAP-DataTypes.ForwardingOptions", reflect.TypeFor[ForwardingOptions]()},
		{"MAP-DataTypes.UserToUserServiceIndicator", reflect.TypeFor[UserToUserServiceIndicator]()},
		{"MAP-DataTypes.MaximumConfereesNumber", reflect.TypeFor[MaximumConfereesNumber]()},
		{"MAP-DataTypes.HuntGroupAccessSelectionOrder", reflect.TypeFor[HuntGroupAccessSelectionOrder]()},
		{"MAP-DataTypes.NoReplyConditionTime", reflect.TypeFor[NoReplyConditionTime]()},
		{"MAP-DataTypes.NumberOfConferees", reflect.TypeFor[NumberOfConferees]()},
		{"MAP-DataTypes.CUG-Facilities", reflect.TypeFor[CUGFacilities]()},
		{"MAP-DataTypes.CUG-Interlock", reflect.TypeFor[CUGInterlock]()},
		{"MAP-DataTypes.CUG-Index", reflect.TypeFor[CUGIndex]()},
		{"MAP-DataTypes.CUG-Options", reflect.TypeFor[CUGOptions]()},
		{"MAP-DataTypes.CUG-Feature", reflect.TypeFor[CUGFeature]()},
		{"MAP-DataTypes.CUG-FeatureList", reflect.TypeFor[CUGFeatureList]()},
		{"MAP-DataTypes.CUG-Information", reflect.TypeFor[CUGInformation]()},
		{"MAP-DataTypes.ForwardingInfo", reflect.TypeFor[ForwardingInfo]()},
		{"MAP-DataTypes.ForwardingData", reflect.TypeFor[ForwardingData]()},
		{"MAP-DataTypes.ForwardingFeature", reflect.TypeFor[ForwardingFeature]()},
		{"MAP-DataTypes.ForwardingFeatureList", reflect.TypeFor[ForwardingFeatureList]()},
		{"MAP-DataTypes.CallBarringInfo", reflect.TypeFor[CallBarringInfo]()},
		{"MAP-DataTypes.CallBarringFeature", reflect.TypeFor[CallBarringFeature]()},
		{"MAP-DataTypes.CallBarringFeatureList", reflect.TypeFor[CallBarringFeatureList]()},
		{"MAP-DataTypes.SubscriberData", reflect.TypeFor[SubscriberData]()},
		{"MAP-DataTypes.SS-Notification", reflect.TypeFor[SSNotification]()},
		{"MAP-DataTypes.Password", reflect.TypeFor[Password]()},
		{"MAP-DataTypes.GuidanceInfo", reflect.TypeFor[GuidanceInfo]()},
		{"MAP-DataTypes.SS-UserData", reflect.TypeFor[SSUserData]()},
		{"MAP-DataTypes.CallReference", reflect.TypeFor[CallReference]()},
		{"MAP-DataTypes.CallType", reflect.TypeFor[CallType]()},
		{"MAP-DataTypes.SS-ChargingData", reflect.TypeFor[SSChargingData]()},
		{"MAP-DataTypes.SS-ChargingInfo", reflect.TypeFor[SSChargingInfo]()},
		{"MAP-DataTypes.CallDuration", reflect.TypeFor[CallDuration]()},
		{"MAP-DataTypes.CallDateTime", reflect.TypeFor[CallDateTime]()},
		{"MAP-DataTypes.PacketDataVolume", reflect.TypeFor[PacketDataVolume]()},
		{"MAP-DataTypes.Charge", reflect.TypeFor[Charge]()},
		{"MAP-DataTypes.ChargingUnit", reflect.TypeFor[ChargingUnit]()},
		{"MAP-DataTypes.CallStatus", reflect.TypeFor[CallStatus]()},
		{"MAP-DataTypes.NumberOfForwarding", reflect.TypeFor[NumberOfForwarding]()},
		{"MAP-DataTypes.ChannelType", reflect.TypeFor[ChannelType]()},
		{"MAP-DataTypes.ClassmarkInformation", reflect.TypeFor[ClassmarkInformation]()},
		{"MAP-DataTypes.HandoverPriority", reflect.TypeFor[HandoverPriority]()},
		{"MAP-DataTypes.HandoverType", reflect.TypeFor[HandoverType]()},
		{"MAP-DataTypes.AuthenticationSet", reflect.TypeFor[AuthenticationSet]()},
		{"MAP-DataTypes.Rand", reflect.TypeFor[Rand]()},
		{"MAP-DataTypes.Sres", reflect.TypeFor[Sres]()},
		{"MAP-DataTypes.Kc", reflect.TypeFor[Kc]()},
		{"MAP-DataTypes.Ki", reflect.TypeFor[Ki]()},
		{"MAP-DataTypes.CKSN", reflect.TypeFor[CKSN]()},
		{"MAP-DataTypes.CipheringMode", reflect.TypeFor[CipheringMode]()},
		{"MAP-DataTypes.SM-RP-DA", reflect.TypeFor[SMRPDA]()},
		{"MAP-DataTypes.SM-RP-OA", reflect.TypeFor[SMRPOA]()},
		{"MAP-DataTypes.SM-RP-UI", reflect.TypeFor[SMRPUI]()},
		{"MAP-DataTypes.TraceReference", reflect.TypeFor[TraceReference]()},
		{"MAP-DataTypes.TraceType", reflect.TypeFor[TraceType]()},
		{"MAP-DataTypes.NetworkResource", reflect.TypeFor[NetworkResource]()},
		{"MAP-DataTypes.RequestParameter", reflect.TypeFor[RequestParameter]()},
		{"MAP-DataTypes.RequestParameters", reflect.TypeFor[RequestParameters]()},
		{"MAP-DataTypes.SentParameter", reflect.TypeFor[SentParameter]()},
		{"MAP-DataTypes.SentParameters", reflect.TypeFor[SentParameters]()},
		{"MAP-DataTypes.CmServiceType", reflect.TypeFor[CmServiceType]()},
		{"MAP-DataTypes.AccessConnectionStatus", reflect.TypeFor[AccessConnectionStatus]()},
		{"MAP-DataTypes.CUG-Information-component1", reflect.TypeFor[CUGInformationComponent1]()},
		{"MAP-Errors.CallBarred-parameter", reflect.TypeFor[CallBarredParameter]()},
		{"MAP-Errors.CUG-Reject-parameter", reflect.TypeFor[CUGRejectParameter]()},
		{"MAP-Errors.PasswordRegistrationFailure-parameter", reflect.TypeFor[PasswordRegistrationFailureParameter]()},
		{"MAP-Errors.SM-DeliveryFailure-parameter", reflect.TypeFor[SMDeliveryFailureParameter]()},
		{"MAP-Errors.SS-Incompatibility-parameter", reflect.TypeFor[SSIncompatibilityParameter]()},
		{"MAP-Operations.ActivateSS-argument", reflect.TypeFor[ActivateSSArgument]()},
		{"MAP-Operations.ActivateTraceMode-argument", reflect.TypeFor[ActivateTraceModeArgument]()},
		{"MAP-Operations.AlertServiceCentre-argument", reflect.TypeFor[AlertServiceCentreArgument]()},
		{"MAP-Operations.Authenticate-argument", reflect.TypeFor[AuthenticateArgument]()},
		{"MAP-Operations.BeginSubscriberActivity-argument", reflect.TypeFor[BeginSubscriberActivityArgument]()},
		{"MAP-Operations.CancelLocation-argument", reflect.TypeFor[CancelLocationArgument]()},
		{"MAP-Operations.CompleteCall-argument", reflect.TypeFor[CompleteCallArgument]()},
		{"MAP-Operations.ConnectToFollowingAddress-argument", reflect.TypeFor[ConnectToFollowingAddressArgument]()},
		{"MAP-Operations.DeactivateSS-argument", reflect.TypeFor[DeactivateSSArgument]()},
		{"MAP-Operations.DeactivateTraceMode-argument", reflect.TypeFor[DeactivateTraceModeArgument]()},
		{"MAP-Operations.DeleteSubscriberData-argument", reflect.TypeFor[DeleteSubscriberDataArgument]()},
		{"MAP-Operations.EraseSS-argument", reflect.TypeFor[EraseSSArgument]()},
		{"MAP-Operations.ForwardShortMessage-argument", reflect.TypeFor[ForwardShortMessageArgument]()},
		{"MAP-Operations.ForwardSsNotification-argument", reflect.TypeFor[ForwardSsNotificationArgument]()},
		{"MAP-Operations.InsertSubscriberData-argument", reflect.TypeFor[InsertSubscriberDataArgument]()},
		{"MAP-Operations.InterrogateSS-argument", reflect.TypeFor[InterrogateSSArgument]()},
		{"MAP-Operations.InterrogateSS-result", reflect.TypeFor[InterrogateSSResult]()},
		{"MAP-Operations.InvokeSS-argument", reflect.TypeFor[InvokeSSArgument]()},
		{"MAP-Operations.NoteInternalHandover-argument", reflect.TypeFor[NoteInternalHandoverArgument]()},
		{"MAP-Operations.Page-argument", reflect.TypeFor[PageArgument]()},
		{"MAP-Operations.PerformHandover-argument", reflect.TypeFor[PerformHandoverArgument]()},
		{"MAP-Operations.PerformHandover-result", reflect.TypeFor[PerformHandoverResult]()},
		{"MAP-Operations.PerformSubsequentHandover-argument", reflect.TypeFor[PerformSubsequentHandoverArgument]()},
		{"MAP-Operations.ProcessAccessRequest-argument", reflect.TypeFor[ProcessAccessRequestArgument]()},
		{"MAP-Operations.ProcessAccessRequest-result", reflect.TypeFor[ProcessAccessRequestResult]()},
		{"MAP-Operations.ProvideRoamingNumber-argument", reflect.TypeFor[ProvideRoamingNumberArgument]()},
		{"MAP-Operations.RegisterChargingInformation-argument", reflect.TypeFor[RegisterChargingInformationArgument]()},
		{"MAP-Operations.RegisterSS-argument", reflect.TypeFor[RegisterSSArgument]()},
		{"MAP-Operations.Reset-argument", reflect.TypeFor[ResetArgument]()},
		{"MAP-Operations.SearchForMobileSubscriber-argument", reflect.TypeFor[SearchForMobileSubscriberArgument]()},
		{"MAP-Operations.SendInfoForIncomingCall-argument", reflect.TypeFor[SendInfoForIncomingCallArgument]()},
		{"MAP-Operations.SendInfoForOutgoingCall-argument", reflect.TypeFor[SendInfoForOutgoingCallArgument]()},
		{"MAP-Operations.SendParameters-argument", reflect.TypeFor[SendParametersArgument]()},
		{"MAP-Operations.SendRoutingInfoForSM-argument", reflect.TypeFor[SendRoutingInfoForSMArgument]()},
		{"MAP-Operations.SendRoutingInfoForSM-result", reflect.TypeFor[SendRoutingInfoForSMResult]()},
		{"MAP-Operations.SendRoutingInformation-argument", reflect.TypeFor[SendRoutingInformationArgument]()},
		{"MAP-Operations.SendRoutingInformation-result", reflect.TypeFor[SendRoutingInformationResult]()},
		{"MAP-Operations.SetCipheringMode-argument", reflect.TypeFor[SetCipheringModeArgument]()},
		{"MAP-Operations.SetMessageWaitingData-argument", reflect.TypeFor[SetMessageWaitingDataArgument]()},
		{"MAP-Operations.TraceSubscriberActivity-argument", reflect.TypeFor[TraceSubscriberActivityArgument]()},
		{"MAP-Operations.UpdateLocation-argument", reflect.TypeFor[UpdateLocationArgument]()},
		{"MAP-Operations.UpdateLocationArea-argument", reflect.TypeFor[UpdateLocationAreaArgument]()},
		{"MAP-Operations.CancelLocation-argument-alternative1", reflect.TypeFor[CancelLocationArgumentAlternative1]()},
		{"MAP-Operations.SearchForMobileSubscriber-argument-storedLocationArea", reflect.TypeFor[SearchForMobileSubscriberArgumentStoredLocationArea]()},
		{"MAP-Operations.SendInfoForIncomingCall-argument-incomingId", reflect.TypeFor[SendInfoForIncomingCallArgumentIncomingId]()},
		{"MAP-Operations.SendRoutingInfoForSM-result-component1", reflect.TypeFor[SendRoutingInfoForSMResultComponent1]()},
		{"MAP-Operations.SendRoutingInfoForSM-result-component1-alternative0", reflect.TypeFor[SendRoutingInfoForSMResultComponent1Alternative0]()},
		{"MAP-Operations.SendRoutingInformation-result-routingInfo", reflect.TypeFor[SendRoutingInformationResultRoutingInfo]()},
		{"MAP-Operations.UpdateLocationArea-argument-previousLocAreaId", reflect.TypeFor[UpdateLocationAreaArgumentPreviousLocAreaId]()},
	} {
		t.Run(row.name, func(t *testing.T) { editionTypedShape(t, row.typ, map[reflect.Type]bool{}) })
	}
}
func editionTypedShape(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[typ] {
		return
	}
	seen[typ] = true
	if typ.Name() == "RawValue" || typ.Kind() == reflect.Interface {
		t.Fatalf("opaque declared source part: %s", typ)
	}
	switch typ.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		editionTypedShape(t, typ.Elem(), seen)
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.IsExported() && f.Tag.Get("asn1") != "-" {
				editionTypedShape(t, f.Type, seen)
			}
		}
	}
}
