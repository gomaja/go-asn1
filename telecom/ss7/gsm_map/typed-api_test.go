// Code generated from the MAP typed API regression contract. DO NOT EDIT.

package gsm_map

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_errors"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes"
)

func TestTypeRefModuleOIDMatchesPinnedSource(t *testing.T) {
	// MAP-SM-DataTypes module identifier, TS 29.002 V19.1.0 §17.6.
	const sourceModuleOID = "0.4.0.0.1.3.16.22"
	info := SendRoutingInfoForSMOperation().Info()
	if info.Argument == nil || info.Argument.ModuleOID != sourceModuleOID {
		t.Fatalf("argument module OID = %+v, want %s", info.Argument, sourceModuleOID)
	}
}

func TestInvalidCodecSentinelAcrossPackages(t *testing.T) {
	var root ValueCodec[int]
	var historical v21_map_er_datatypes.ValueCodec[int]
	for _, decode := range []func() error{
		func() error { _, err := root.DecodeBER(nil); return err },
		func() error { _, err := historical.DecodeBER(nil); return err },
	} {
		if err := decode(); !errors.Is(err, ber.ErrInvalidCodec) {
			t.Fatalf("zero codec returned %v", err)
		}
	}
}

func TestInvalidBindingSentinel(t *testing.T) {
	var mapOperation Operation[SendRoutingInfoArg, SendRoutingInfoRes, SendRoutingInfoErrors]
	var ssOperation SSOperation[BERValue[SSUserData], BERValue[SSUserData], SSProcessUnstructuredSSDataErrors]
	for _, attempt := range []func() error{
		func() error { _, err := mapOperation.DecodeError(0, nil, false); return err },
		func() error { _, err := mapOperation.EncodeError(SendRoutingInfoErrors{}); return err },
		func() error { _, err := ssOperation.DecodeError(0, nil, false); return err },
		func() error { _, err := ssOperation.EncodeError(SSProcessUnstructuredSSDataErrors{}); return err },
		func() error { _, err := SendRoutingInfoOperation().DecodeError(-1, nil, false); return err },
	} {
		if err := attempt(); !errors.Is(err, ber.ErrInvalidBinding) {
			t.Fatalf("descriptor returned %v", err)
		}
	}
}

func TestEveryTypedBindingCompiles(t *testing.T) {
	var _ Operation[SendRoutingInfoArg, SendRoutingInfoRes, SendRoutingInfoErrors] = SendRoutingInfoOperation()
	var _ Operation[ProvideRoamingNumberArg, ProvideRoamingNumberRes, ProvideRoamingNumberErrors] = ProvideRoamingNumberOperation()
	var _ Operation[ResumeCallHandlingArg, ResumeCallHandlingRes, ResumeCallHandlingErrors] = ResumeCallHandlingOperation()
	var _ Operation[SetReportingStateArg, SetReportingStateRes, SetReportingStateErrors] = SetReportingStateOperation()
	var _ Operation[StatusReportArg, StatusReportRes, StatusReportErrors] = StatusReportOperation()
	var _ Operation[RemoteUserFreeArg, RemoteUserFreeRes, RemoteUserFreeErrors] = RemoteUserFreeOperation()
	var _ Operation[ISTAlertArg, ISTAlertRes, IstAlertErrors] = IstAlertOperation()
	var _ Operation[ISTCommandArg, ISTCommandRes, IstCommandErrors] = IstCommandOperation()
	var _ Operation[ReleaseResourcesArg, ReleaseResourcesRes, ReleaseResourcesErrors] = ReleaseResourcesOperation()
	var _ Operation[PrepareGroupCallArg, PrepareGroupCallRes, PrepareGroupCallErrors] = PrepareGroupCallOperation()
	var _ Operation[SendGroupCallEndSignalArg, SendGroupCallEndSignalRes, SendGroupCallEndSignalErrors] = SendGroupCallEndSignalOperation()
	var _ Operation[ProcessGroupCallSignallingArg, NoParameter, ProcessGroupCallSignallingErrors] = ProcessGroupCallSignallingOperation()
	var _ Operation[ForwardGroupCallSignallingArg, NoParameter, ForwardGroupCallSignallingErrors] = ForwardGroupCallSignallingOperation()
	var _ Operation[SendGroupCallInfoArg, SendGroupCallInfoRes, SendGroupCallInfoErrors] = SendGroupCallInfoOperation()
	var _ Operation[RoutingInfoForLCSArg, RoutingInfoForLCSRes, SendRoutingInfoForLCSErrors] = SendRoutingInfoForLCSOperation()
	var _ Operation[ProvideSubscriberLocationArg, ProvideSubscriberLocationRes, ProvideSubscriberLocationErrors] = ProvideSubscriberLocationOperation()
	var _ Operation[SubscriberLocationReportArg, SubscriberLocationReportRes, SubscriberLocationReportErrors] = SubscriberLocationReportOperation()
	var _ Operation[UpdateLocationArg, UpdateLocationRes, UpdateLocationErrors] = UpdateLocationOperation()
	var _ Operation[CancelLocationArg, CancelLocationRes, CancelLocationErrors] = CancelLocationOperation()
	var _ Operation[PurgeMSArg, PurgeMSRes, PurgeMSErrors] = PurgeMSOperation()
	var _ Operation[SendIdentificationArg, SendIdentificationRes, SendIdentificationErrors] = SendIdentificationOperation()
	var _ Operation[UpdateGprsLocationArg, UpdateGprsLocationRes, UpdateGprsLocationErrors] = UpdateGprsLocationOperation()
	var _ Operation[ProvideSubscriberInfoArg, ProvideSubscriberInfoRes, ProvideSubscriberInfoErrors] = ProvideSubscriberInfoOperation()
	var _ Operation[AnyTimeInterrogationArg, AnyTimeInterrogationRes, AnyTimeInterrogationErrors] = AnyTimeInterrogationOperation()
	var _ Operation[AnyTimeSubscriptionInterrogationArg, AnyTimeSubscriptionInterrogationRes, AnyTimeSubscriptionInterrogationErrors] = AnyTimeSubscriptionInterrogationOperation()
	var _ Operation[AnyTimeModificationArg, AnyTimeModificationRes, AnyTimeModificationErrors] = AnyTimeModificationOperation()
	var _ Operation[NoteSubscriberDataModifiedArg, NoteSubscriberDataModifiedRes, NoteSubscriberDataModifiedErrors] = NoteSubscriberDataModifiedOperation()
	var _ Operation[PrepareHOArg, PrepareHORes, PrepareHandoverErrors] = PrepareHandoverOperation()
	var _ Operation[SendEndSignalArg, SendEndSignalRes, SendEndSignalErrors] = SendEndSignalOperation()
	var _ Operation[ProcessAccessSignallingArg, NoParameter, ProcessAccessSignallingErrors] = ProcessAccessSignallingOperation()
	var _ Operation[ForwardAccessSignallingArg, NoParameter, ForwardAccessSignallingErrors] = ForwardAccessSignallingOperation()
	var _ Operation[PrepareSubsequentHOArg, PrepareSubsequentHORes, PrepareSubsequentHandoverErrors] = PrepareSubsequentHandoverOperation()
	var _ Operation[SendAuthenticationInfoArg, SendAuthenticationInfoRes, SendAuthenticationInfoErrors] = SendAuthenticationInfoOperation()
	var _ Operation[AuthenticationFailureReportArg, AuthenticationFailureReportRes, AuthenticationFailureReportErrors] = AuthenticationFailureReportOperation()
	var _ Operation[CheckIMEIArg, CheckIMEIRes, CheckIMEIErrors] = CheckIMEIOperation()
	var _ Operation[InsertSubscriberDataArg, InsertSubscriberDataRes, InsertSubscriberDataErrors] = InsertSubscriberDataOperation()
	var _ Operation[DeleteSubscriberDataArg, DeleteSubscriberDataRes, DeleteSubscriberDataErrors] = DeleteSubscriberDataOperation()
	var _ Operation[ResetArg, NoParameter, ResetErrors] = ResetOperation()
	var _ Operation[NoParameter, NoParameter, ForwardCheckSSIndicationErrors] = ForwardCheckSSIndicationOperation()
	var _ Operation[RestoreDataArg, RestoreDataRes, RestoreDataErrors] = RestoreDataOperation()
	var _ Operation[SendRoutingInfoForGprsArg, SendRoutingInfoForGprsRes, SendRoutingInfoForGprsErrors] = SendRoutingInfoForGprsOperation()
	var _ Operation[FailureReportArg, FailureReportRes, FailureReportErrors] = FailureReportOperation()
	var _ Operation[NoteMsPresentForGprsArg, NoteMsPresentForGprsRes, NoteMsPresentForGprsErrors] = NoteMsPresentForGprsOperation()
	var _ Operation[NoteMMEventArg, NoteMMEventRes, NoteMMEventErrors] = NoteMMEventOperation()
	var _ Operation[UpdateVcsgLocationArg, UpdateVcsgLocationRes, UpdateVcsgLocationErrors] = UpdateVcsgLocationOperation()
	var _ Operation[CancelVcsgLocationArg, CancelVcsgLocationRes, CancelVcsgLocationErrors] = CancelVcsgLocationOperation()
	var _ Operation[ActivateTraceModeArg, ActivateTraceModeRes, ActivateTraceModeErrors] = ActivateTraceModeOperation()
	var _ Operation[DeactivateTraceModeArg, DeactivateTraceModeRes, DeactivateTraceModeErrors] = DeactivateTraceModeOperation()
	var _ Operation[BERValue[ISDNAddressString], BERValue[IMSI], SendIMSIErrors] = SendIMSIOperation()
	var _ Operation[RoutingInfoForSMArg, RoutingInfoForSMRes, SendRoutingInfoForSMErrors] = SendRoutingInfoForSMOperation()
	var _ Operation[MOForwardSMArg, MOForwardSMRes, MoForwardSMErrors] = MoForwardSMOperation()
	var _ Operation[MTForwardSMArg, MTForwardSMRes, MtForwardSMErrors] = MtForwardSMOperation()
	var _ Operation[ReportSMDeliveryStatusArg, ReportSMDeliveryStatusRes, ReportSMDeliveryStatusErrors] = ReportSMDeliveryStatusOperation()
	var _ Operation[AlertServiceCentreArg, NoParameter, AlertServiceCentreErrors] = AlertServiceCentreOperation()
	var _ Operation[InformServiceCentreArg, NoParameter, InformServiceCentreErrors] = InformServiceCentreOperation()
	var _ Operation[ReadyForSMArg, ReadyForSMRes, ReadyForSMErrors] = ReadyForSMOperation()
	var _ Operation[MTForwardSMVGCSArg, MTForwardSMVGCSRes, MtForwardSMVGCSErrors] = MtForwardSMVGCSOperation()
	var _ Operation[RegisterSSArg, SSInfo, RegisterSSErrors] = RegisterSSOperation()
	var _ Operation[SSForBSCode, SSInfo, EraseSSErrors] = EraseSSOperation()
	var _ Operation[SSForBSCode, SSInfo, ActivateSSErrors] = ActivateSSOperation()
	var _ Operation[SSForBSCode, SSInfo, DeactivateSSErrors] = DeactivateSSOperation()
	var _ Operation[SSForBSCode, InterrogateSSRes, InterrogateSSErrors] = InterrogateSSOperation()
	var _ Operation[USSDArg, USSDRes, ProcessUnstructuredSSRequestErrors] = ProcessUnstructuredSSRequestOperation()
	var _ Operation[USSDArg, USSDRes, UnstructuredSSRequestErrors] = UnstructuredSSRequestOperation()
	var _ Operation[USSDArg, NoParameter, UnstructuredSSNotifyErrors] = UnstructuredSSNotifyOperation()
	var _ Operation[BERValue[SSCode], BERValue[Password], RegisterPasswordErrors] = RegisterPasswordOperation()
	var _ Operation[BERValue[GuidanceInfo], BERValue[Password], GetPasswordErrors] = GetPasswordOperation()
	var _ Operation[SSInvocationNotificationArg, SSInvocationNotificationRes, SsInvocationNotificationErrors] = SsInvocationNotificationOperation()
	var _ Operation[RegisterCCEntryArg, RegisterCCEntryRes, RegisterCCEntryErrors] = RegisterCCEntryOperation()
	var _ Operation[EraseCCEntryArg, EraseCCEntryRes, EraseCCEntryErrors] = EraseCCEntryOperation()
	var _ SSOperation[BERValue[SSUserData], BERValue[SSUserData], SSProcessUnstructuredSSDataErrors] = SSProcessUnstructuredSSDataOperation()
	var _ SSOperation[NotifySSArg, NoParameter, SSNotifySSErrors] = SSNotifySSOperation()
	var _ SSOperation[ForwardChargeAdviceArg, NoParameter, SSForwardChargeAdviceErrors] = SSForwardChargeAdviceOperation()
	var _ SSOperation[ForwardCUGInfoArg, NoParameter, SSForwardCUGInfoErrors] = SSForwardCUGInfoOperation()
	var _ SSOperation[NoParameter, NoParameter, SSBuildMPTYErrors] = SSBuildMPTYOperation()
	var _ SSOperation[NoParameter, NoParameter, SSHoldMPTYErrors] = SSHoldMPTYOperation()
	var _ SSOperation[NoParameter, NoParameter, SSRetrieveMPTYErrors] = SSRetrieveMPTYOperation()
	var _ SSOperation[NoParameter, NoParameter, SSSplitMPTYErrors] = SSSplitMPTYOperation()
	var _ SSOperation[NoParameter, NoParameter, SSExplicitCTErrors] = SSExplicitCTOperation()
	var _ SSOperation[AccessRegisterCCEntryArg, v21_map_ss_datatypes.SSRegisterCCEntryRes, SSAccessRegisterCCEntryErrors] = SSAccessRegisterCCEntryOperation()
	var _ SSOperation[CallDeflectionArg, NoParameter, SSCallDeflectionErrors] = SSCallDeflectionOperation()
	var _ SSOperation[UserUserServiceArg, NoParameter, SSUserUserServiceErrors] = SSUserUserServiceOperation()
	var _ SSOperation[LocationNotificationArg, LocationNotificationRes, SSLcsLocationNotificationErrors] = SSLcsLocationNotificationOperation()
	var _ SSOperation[LCSMOLRArg, LCSMOLRRes, SSLcsMOLRErrors] = SSLcsMOLROperation()
	var _ SSOperation[LCSAreaEventRequestArg, NoParameter, SSLcsAreaEventRequestErrors] = SSLcsAreaEventRequestOperation()
	var _ SSOperation[LCSAreaEventReportArg, NoParameter, SSLcsAreaEventReportErrors] = SSLcsAreaEventReportOperation()
	var _ SSOperation[LCSAreaEventCancellationArg, NoParameter, SSLcsAreaEventCancellationErrors] = SSLcsAreaEventCancellationOperation()
	var _ SSOperation[LCSPeriodicLocationRequestArg, LCSPeriodicLocationRequestRes, SSLcsPeriodicLocationRequestErrors] = SSLcsPeriodicLocationRequestOperation()
	var _ SSOperation[LCSLocationUpdateArg, LCSLocationUpdateRes, SSLcsLocationUpdateErrors] = SSLcsLocationUpdateOperation()
	var _ SSOperation[LCSPeriodicLocationCancellationArg, NoParameter, SSLcsPeriodicLocationCancellationErrors] = SSLcsPeriodicLocationCancellationOperation()
	var _ SSOperation[LCSPeriodicTriggeredInvokeArg, LCSPeriodicTriggeredInvokeRes, SSLcsPeriodicTriggeredInvokeErrors] = SSLcsPeriodicTriggeredInvokeOperation()
	var _ SSOperation[LCSEventReportArg, LCSEventReportRes, SSLcsEventReportErrors] = SSLcsEventReportOperation()
	var _ SSOperation[LCSCancelDeferredLocationArg, NoParameter, SSLcsCancelDeferredLocationErrors] = SSLcsCancelDeferredLocationOperation()
	var _ SSOperation[LCSCancelDeferredLocationArg, NoParameter, SSLcsMSCancelDeferredLocationErrors] = SSLcsMSCancelDeferredLocationOperation()
	var _ SSOperation[LCSLocationPrivacySettingArg, NoParameter, SSLcsLocationPrivacySettingErrors] = SSLcsLocationPrivacySettingOperation()
	var _ SSOperation[LCSPruAssociationArg, LCSPruAssociationRes, SSLcsPruAssociationErrors] = SSLcsPruAssociationOperation()
	var _ SSOperation[LCSPruDisassociationArg, NoParameter, SSLcsPruDisassociationErrors] = SSLcsPruDisassociationOperation()
	var _ SSOperation[LCSSLMOLRArg, LCSSLMOLRRes, SSLcsSLMOLRErrors] = SSLcsSLMOLROperation()
	var _ SSOperation[LCSSLMTLRArg, LCSSLMTLRRes, SSLcsSLMTLRErrors] = SSLcsSLMTLROperation()
	var _ SSOperation[LCSDLRSPPTransportArg, LCSDLRSPPTransportRes, SSLcsDLRSPPTransportErrors] = SSLcsDLRSPPTransportOperation()
	var _ SSOperation[LCSULRSPPTransportArg, LCSULRSPPTransportRes, SSLcsULRSPPTransportErrors] = SSLcsULRSPPTransportOperation()
	var _ ErrorDescriptor[SystemFailureParam] = SystemFailureErrorDescriptor()
	var _ ErrorDescriptor[DataMissingParam] = DataMissingErrorDescriptor()
	var _ ErrorDescriptor[UnexpectedDataParam] = UnexpectedDataValueErrorDescriptor()
	var _ ErrorDescriptor[FacilityNotSupParam] = FacilityNotSupportedErrorDescriptor()
	var _ ErrorDescriptor[IncompatibleTerminalParam] = IncompatibleTerminalErrorDescriptor()
	var _ ErrorDescriptor[ResourceLimitationParam] = ResourceLimitationErrorDescriptor()
	var _ ErrorDescriptor[UnknownSubscriberParam] = UnknownSubscriberErrorDescriptor()
	var _ ErrorDescriptor[NumberChangedParam] = NumberChangedErrorDescriptor()
	var _ ErrorDescriptor[NoParameter] = UnknownMSCErrorDescriptor()
	var _ ErrorDescriptor[UnidentifiedSubParam] = UnidentifiedSubscriberErrorDescriptor()
	var _ ErrorDescriptor[NoParameter] = UnknownEquipmentErrorDescriptor()
	var _ ErrorDescriptor[RoamingNotAllowedParam] = RoamingNotAllowedErrorDescriptor()
	var _ ErrorDescriptor[IllegalSubscriberParam] = IllegalSubscriberErrorDescriptor()
	var _ ErrorDescriptor[IllegalEquipmentParam] = IllegalEquipmentErrorDescriptor()
	var _ ErrorDescriptor[BearerServNotProvParam] = BearerServiceNotProvisionedErrorDescriptor()
	var _ ErrorDescriptor[TeleservNotProvParam] = TeleserviceNotProvisionedErrorDescriptor()
	var _ ErrorDescriptor[NoParameter] = NoHandoverNumberAvailableErrorDescriptor()
	var _ ErrorDescriptor[NoParameter] = SubsequentHandoverFailureErrorDescriptor()
	var _ ErrorDescriptor[TargetCellOutsideGCAParam] = TargetCellOutsideGroupCallAreaErrorDescriptor()
	var _ ErrorDescriptor[TracingBufferFullParam] = TracingBufferFullErrorDescriptor()
	var _ ErrorDescriptor[NoRoamingNbParam] = NoRoamingNumberAvailableErrorDescriptor()
	var _ ErrorDescriptor[AbsentSubscriberParam] = AbsentSubscriberErrorDescriptor()
	var _ ErrorDescriptor[BusySubscriberParam] = BusySubscriberErrorDescriptor()
	var _ ErrorDescriptor[NoSubscriberReplyParam] = NoSubscriberReplyErrorDescriptor()
	var _ ErrorDescriptor[CallBarredParam] = CallBarredErrorDescriptor()
	var _ ErrorDescriptor[ForwardingViolationParam] = ForwardingViolationErrorDescriptor()
	var _ ErrorDescriptor[ForwardingFailedParam] = ForwardingFailedErrorDescriptor()
	var _ ErrorDescriptor[CUGRejectParam] = CugRejectErrorDescriptor()
	var _ ErrorDescriptor[ORNotAllowedParam] = OrNotAllowedErrorDescriptor()
	var _ ErrorDescriptor[ATINotAllowedParam] = AtiNotAllowedErrorDescriptor()
	var _ ErrorDescriptor[ATSINotAllowedParam] = AtsiNotAllowedErrorDescriptor()
	var _ ErrorDescriptor[ATMNotAllowedParam] = AtmNotAllowedErrorDescriptor()
	var _ ErrorDescriptor[InformationNotAvailableParam] = InformationNotAvailableErrorDescriptor()
	var _ ErrorDescriptor[IllegalSSOperationParam] = IllegalSSOperationErrorDescriptor()
	var _ ErrorDescriptor[BERValue[SSStatus]] = SsErrorStatusErrorDescriptor()
	var _ ErrorDescriptor[SSNotAvailableParam] = SsNotAvailableErrorDescriptor()
	var _ ErrorDescriptor[SSSubscriptionViolationParam] = SsSubscriptionViolationErrorDescriptor()
	var _ ErrorDescriptor[SSIncompatibilityCause] = SsIncompatibilityErrorDescriptor()
	var _ ErrorDescriptor[NoParameter] = UnknownAlphabetErrorDescriptor()
	var _ ErrorDescriptor[NoParameter] = UssdBusyErrorDescriptor()
	var _ ErrorDescriptor[BERValue[PWRegistrationFailureCause]] = PwRegistrationFailureErrorDescriptor()
	var _ ErrorDescriptor[NoParameter] = NegativePWCheckErrorDescriptor()
	var _ ErrorDescriptor[NoParameter] = NumberOfPWAttemptsViolationErrorDescriptor()
	var _ ErrorDescriptor[ShortTermDenialParam] = ShortTermDenialErrorDescriptor()
	var _ ErrorDescriptor[LongTermDenialParam] = LongTermDenialErrorDescriptor()
	var _ ErrorDescriptor[SubBusyForMTSMSParam] = SubscriberBusyForMTSMSErrorDescriptor()
	var _ ErrorDescriptor[SMDeliveryFailureCause] = SmDeliveryFailureErrorDescriptor()
	var _ ErrorDescriptor[MessageWaitListFullParam] = MessageWaitingListFullErrorDescriptor()
	var _ ErrorDescriptor[AbsentSubscriberSMParam] = AbsentSubscriberSMErrorDescriptor()
	var _ ErrorDescriptor[NoGroupCallNbParam] = NoGroupCallNumberAvailableErrorDescriptor()
	var _ ErrorDescriptor[OngoingGroupCallParam] = OngoingGroupCallErrorDescriptor()
	var _ ErrorDescriptor[UnauthorizedRequestingNetworkParam] = UnauthorizedRequestingNetworkErrorDescriptor()
	var _ ErrorDescriptor[UnauthorizedLCSClientParam] = UnauthorizedLCSClientErrorDescriptor()
	var _ ErrorDescriptor[PositionMethodFailureParam] = PositionMethodFailureErrorDescriptor()
	var _ ErrorDescriptor[UnknownOrUnreachableLCSClientParam] = UnknownOrUnreachableLCSClientErrorDescriptor()
	var _ ErrorDescriptor[MMEventNotSupportedParam] = MmEventNotSupportedErrorDescriptor()
	var _ SSErrorDescriptor[NoParameter] = SSResourcesNotAvailableErrorDescriptor()
	var _ SSErrorDescriptor[NoParameter] = SSMaxNumberOfMPTYParticipantsExceededErrorDescriptor()
	var _ SSErrorDescriptor[NoParameter] = SSInvalidDeflectedToNumberErrorDescriptor()
	var _ SSErrorDescriptor[NoParameter] = SSSpecialServiceCodeErrorDescriptor()
	var _ SSErrorDescriptor[NoParameter] = SSDeflectionToServedSubscriberErrorDescriptor()
	var _ SSErrorDescriptor[NoParameter] = SSRejectedByNetworkErrorDescriptor()
	var _ SSErrorDescriptor[NoParameter] = SSRejectedByUserErrorDescriptor()
	var _ SSErrorDescriptor[NoParameter] = SSLcsInvalidPruErrorDescriptor()
	var _ SSErrorDescriptor[PruAssociationRejParam] = SSLcsPruAssociationRejErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERSystemFailureParam] = v21_map_errors.HistoricalMAPErrorsSystemFailureErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERDataMissingParam] = v21_map_errors.HistoricalMAPErrorsDataMissingErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERUnexpectedDataParam] = v21_map_errors.HistoricalMAPErrorsUnexpectedDataValueErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERFacilityNotSupParam] = v21_map_errors.HistoricalMAPErrorsFacilityNotSupportedErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERIncompatibleTerminalParam] = v21_map_errors.HistoricalMAPErrorsIncompatibleTerminalErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERResourceLimitationParam] = v21_map_errors.HistoricalMAPErrorsResourceLimitationErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERUnknownSubscriberParam] = v21_map_errors.HistoricalMAPErrorsUnknownSubscriberErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERNumberChangedParam] = v21_map_errors.HistoricalMAPErrorsNumberChangedErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_errors.NoParameter] = v21_map_errors.HistoricalMAPErrorsUnknownMSCErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERUnidentifiedSubParam] = v21_map_errors.HistoricalMAPErrorsUnidentifiedSubscriberErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_errors.NoParameter] = v21_map_errors.HistoricalMAPErrorsUnknownEquipmentErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERRoamingNotAllowedParam] = v21_map_errors.HistoricalMAPErrorsRoamingNotAllowedErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERIllegalSubscriberParam] = v21_map_errors.HistoricalMAPErrorsIllegalSubscriberErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERIllegalEquipmentParam] = v21_map_errors.HistoricalMAPErrorsIllegalEquipmentErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERBearerServNotProvParam] = v21_map_errors.HistoricalMAPErrorsBearerServiceNotProvisionedErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERTeleservNotProvParam] = v21_map_errors.HistoricalMAPErrorsTeleserviceNotProvisionedErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_errors.NoParameter] = v21_map_errors.HistoricalMAPErrorsNoHandoverNumberAvailableErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_errors.NoParameter] = v21_map_errors.HistoricalMAPErrorsSubsequentHandoverFailureErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERTargetCellOutsideGCAParam] = v21_map_errors.HistoricalMAPErrorsTargetCellOutsideGroupCallAreaErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERTracingBufferFullParam] = v21_map_errors.HistoricalMAPErrorsTracingBufferFullErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERNoRoamingNbParam] = v21_map_errors.HistoricalMAPErrorsNoRoamingNumberAvailableErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERAbsentSubscriberParam] = v21_map_errors.HistoricalMAPErrorsAbsentSubscriberErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERBusySubscriberParam] = v21_map_errors.HistoricalMAPErrorsBusySubscriberErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERNoSubscriberReplyParam] = v21_map_errors.HistoricalMAPErrorsNoSubscriberReplyErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERCallBarredParam] = v21_map_errors.HistoricalMAPErrorsCallBarredErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERForwardingViolationParam] = v21_map_errors.HistoricalMAPErrorsForwardingViolationErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERForwardingFailedParam] = v21_map_errors.HistoricalMAPErrorsForwardingFailedErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERCUGRejectParam] = v21_map_errors.HistoricalMAPErrorsCugRejectErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERORNotAllowedParam] = v21_map_errors.HistoricalMAPErrorsOrNotAllowedErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERATINotAllowedParam] = v21_map_errors.HistoricalMAPErrorsAtiNotAllowedErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERATSINotAllowedParam] = v21_map_errors.HistoricalMAPErrorsAtsiNotAllowedErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERATMNotAllowedParam] = v21_map_errors.HistoricalMAPErrorsAtmNotAllowedErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERInformationNotAvailableParam] = v21_map_errors.HistoricalMAPErrorsInformationNotAvailableErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERIllegalSSOperationParam] = v21_map_errors.HistoricalMAPErrorsIllegalSSOperationErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]] = v21_map_errors.HistoricalMAPErrorsSsErrorStatusErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERSSNotAvailableParam] = v21_map_errors.HistoricalMAPErrorsSsNotAvailableErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERSSSubscriptionViolationParam] = v21_map_errors.HistoricalMAPErrorsSsSubscriptionViolationErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERSSIncompatibilityCause] = v21_map_errors.HistoricalMAPErrorsSsIncompatibilityErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_errors.NoParameter] = v21_map_errors.HistoricalMAPErrorsUnknownAlphabetErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_errors.NoParameter] = v21_map_errors.HistoricalMAPErrorsUssdBusyErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.BERValue[v21_map_er_datatypes.ERPWRegistrationFailureCause]] = v21_map_errors.HistoricalMAPErrorsPwRegistrationFailureErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_errors.NoParameter] = v21_map_errors.HistoricalMAPErrorsNegativePWCheckErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_errors.NoParameter] = v21_map_errors.HistoricalMAPErrorsNumberOfPWAttemptsViolationErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERShortTermDenialParam] = v21_map_errors.HistoricalMAPErrorsShortTermDenialErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERLongTermDenialParam] = v21_map_errors.HistoricalMAPErrorsLongTermDenialErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERSubBusyForMTSMSParam] = v21_map_errors.HistoricalMAPErrorsSubscriberBusyForMTSMSErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERSMDeliveryFailureCause] = v21_map_errors.HistoricalMAPErrorsSmDeliveryFailureErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERMessageWaitListFullParam] = v21_map_errors.HistoricalMAPErrorsMessageWaitingListFullErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERAbsentSubscriberSMParam] = v21_map_errors.HistoricalMAPErrorsAbsentSubscriberSMErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERNoGroupCallNbParam] = v21_map_errors.HistoricalMAPErrorsNoGroupCallNumberAvailableErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.EROngoingGroupCallParam] = v21_map_errors.HistoricalMAPErrorsOngoingGroupCallErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERUnauthorizedRequestingNetworkParam] = v21_map_errors.HistoricalMAPErrorsUnauthorizedRequestingNetworkErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERUnauthorizedLCSClientParam] = v21_map_errors.HistoricalMAPErrorsUnauthorizedLCSClientErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERPositionMethodFailureParam] = v21_map_errors.HistoricalMAPErrorsPositionMethodFailureErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERUnknownOrUnreachableLCSClientParam] = v21_map_errors.HistoricalMAPErrorsUnknownOrUnreachableLCSClientErrorDescriptor()
	var _ v21_map_errors.HistoricalMAPErrorDescriptor[v21_map_er_datatypes.ERMMEventNotSupportedParam] = v21_map_errors.HistoricalMAPErrorsMmEventNotSupportedErrorDescriptor()
}

type bindingRow struct {
	Name, Module, SHA256, Argument, Result, Parameter string
	Code                                              int64
	Errors, Linked                                    []string
	ReturnResult                                      bool         `json:"return_result"`
	ReturnResultExplicit                              bool         `json:"return_result_explicit"`
	ErrorBindings                                     []bindingRow `json:"error_bindings"`
}

func bindingRows(t *testing.T, data string) []bindingRow {
	t.Helper()
	var rows []bindingRow
	if err := json.Unmarshal([]byte(data), &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}
func checkBindingType(t *testing.T, got *TypeRef, name string) {
	t.Helper()
	if name == "" {
		if got != nil {
			t.Fatalf("unexpected type %+v", got)
		}
		return
	}
	if got == nil || got.ASN1Name != name || got.GoName == "" || got.GoPackage == "" || got.ModuleOID == "" {
		t.Fatalf("type %+v, want source %s", got, name)
	}
}
func checkBindingSource(t *testing.T, source SourceRef, row bindingRow) {
	t.Helper()
	document, edition := "3GPP TS 29.002", "19.1.0"
	if strings.HasPrefix(row.Module, "SS-") {
		document, edition = "3GPP TS 24.080", "19.4.0"
	} else if row.SHA256 == "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" {
		edition = "18.0.0"
	}
	if source.Document != document || source.Edition != edition {
		t.Fatalf("source edition %+v, want %s %s", source, document, edition)
	}

	if source.Module != row.Module || source.Assignment != row.Name || source.SHA256 != row.SHA256 || source.Clause == "" || source.Document == "" || source.Edition == "" {
		t.Fatalf("source %+v, want %+v", source, row)
	}
}

// The locked source SHA includes the approved visible LINKED extraction
// exception documented in spec/SOURCES.md; the reviewed table predates it.
func TestCompleteMAPDescriptorCatalogue(t *testing.T) {
	rows := bindingRows(t, `[{"name":"sendRoutingInfo","module":"MAP-CallHandlingOperations","sha256":"c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d","argument":"SendRoutingInfoArg","result":"SendRoutingInfoRes","errors":["systemFailure","dataMissing","unexpectedDataValue","facilityNotSupported","or-NotAllowed","unknownSubscriber","numberChanged","bearerServiceNotProvisioned","teleserviceNotProvisioned","absentSubscriber","busySubscriber","noSubscriberReply","callBarred","cug-Reject","forwardingViolation"],"linked":[],"return_result":true,"return_result_explicit":false,"code":22},{"name":"provideRoamingNumber","module":"MAP-CallHandlingOperations","sha256":"c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d","argument":"ProvideRoamingNumberArg","result":"ProvideRoamingNumberRes","errors":["systemFailure","dataMissing","unexpectedDataValue","facilityNotSupported","or-NotAllowed","absentSubscriber","noRoamingNumberAvailable"],"linked":[],"return_result":true,"return_result_explicit":false,"code":4},{"name":"resumeCallHandling","module":"MAP-CallHandlingOperations","sha256":"c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d","argument":"ResumeCallHandlingArg","result":"ResumeCallHandlingRes","errors":["forwardingFailed","or-NotAllowed","unexpectedDataValue","dataMissing"],"linked":[],"return_result":true,"return_result_explicit":false,"code":6},{"name":"setReportingState","module":"MAP-CallHandlingOperations","sha256":"c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d","argument":"SetReportingStateArg","result":"SetReportingStateRes","errors":["systemFailure","unidentifiedSubscriber","unexpectedDataValue","dataMissing","resourceLimitation","facilityNotSupported"],"linked":[],"return_result":true,"return_result_explicit":false,"code":73},{"name":"statusReport","module":"MAP-CallHandlingOperations","sha256":"c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d","argument":"StatusReportArg","result":"StatusReportRes","errors":["unknownSubscriber","systemFailure","unexpectedDataValue","dataMissing"],"linked":[],"return_result":true,"return_result_explicit":false,"code":74},{"name":"remoteUserFree","module":"MAP-CallHandlingOperations","sha256":"c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d","argument":"RemoteUserFreeArg","result":"RemoteUserFreeRes","errors":["unexpectedDataValue","dataMissing","incompatibleTerminal","absentSubscriber","systemFailure","busySubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":75},{"name":"ist-Alert","module":"MAP-CallHandlingOperations","sha256":"c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d","argument":"IST-AlertArg","result":"IST-AlertRes","errors":["unexpectedDataValue","resourceLimitation","unknownSubscriber","systemFailure","facilityNotSupported"],"linked":[],"return_result":true,"return_result_explicit":false,"code":87},{"name":"ist-Command","module":"MAP-CallHandlingOperations","sha256":"c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d","argument":"IST-CommandArg","result":"IST-CommandRes","errors":["unexpectedDataValue","resourceLimitation","unknownSubscriber","systemFailure","facilityNotSupported"],"linked":[],"return_result":true,"return_result_explicit":false,"code":88},{"name":"releaseResources","module":"MAP-CallHandlingOperations","sha256":"c61f10b3a81b1206acd7d36318c56a7cb3e0a212a4de53d2f5f705bf7cde4a1d","argument":"ReleaseResourcesArg","result":"ReleaseResourcesRes","errors":["unexpectedDataValue","systemFailure"],"linked":[],"return_result":true,"return_result_explicit":false,"code":20},{"name":"prepareGroupCall","module":"MAP-Group-Call-Operations","sha256":"2047261424cb7e0de50d6507e142ce3c4439a628ad5a273efc8e4ddefe1087f6","argument":"PrepareGroupCallArg","result":"PrepareGroupCallRes","errors":["systemFailure","noGroupCallNumberAvailable","unexpectedDataValue"],"linked":[],"return_result":true,"return_result_explicit":false,"code":39},{"name":"sendGroupCallEndSignal","module":"MAP-Group-Call-Operations","sha256":"2047261424cb7e0de50d6507e142ce3c4439a628ad5a273efc8e4ddefe1087f6","argument":"SendGroupCallEndSignalArg","result":"SendGroupCallEndSignalRes","errors":[],"linked":[],"return_result":true,"return_result_explicit":false,"code":40},{"name":"processGroupCallSignalling","module":"MAP-Group-Call-Operations","sha256":"2047261424cb7e0de50d6507e142ce3c4439a628ad5a273efc8e4ddefe1087f6","argument":"ProcessGroupCallSignallingArg","errors":[],"linked":[],"return_result":true,"return_result_explicit":false,"code":41},{"name":"forwardGroupCallSignalling","module":"MAP-Group-Call-Operations","sha256":"2047261424cb7e0de50d6507e142ce3c4439a628ad5a273efc8e4ddefe1087f6","argument":"ForwardGroupCallSignallingArg","errors":[],"linked":[],"return_result":true,"return_result_explicit":false,"code":42},{"name":"sendGroupCallInfo","module":"MAP-Group-Call-Operations","sha256":"2047261424cb7e0de50d6507e142ce3c4439a628ad5a273efc8e4ddefe1087f6","argument":"SendGroupCallInfoArg","result":"SendGroupCallInfoRes","errors":["systemFailure","ongoingGroupCall","unexpectedDataValue","dataMissing","teleserviceNotProvisioned","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":84},{"name":"sendRoutingInfoForLCS","module":"MAP-LocationServiceOperations","sha256":"280414f331b25e83c672dc7ce1773e9e4f1585f1d0f3f374bd98637e11ad6b0a","argument":"RoutingInfoForLCS-Arg","result":"RoutingInfoForLCS-Res","errors":["systemFailure","dataMissing","unexpectedDataValue","facilityNotSupported","unknownSubscriber","absentSubscriber","unauthorizedRequestingNetwork"],"linked":[],"return_result":true,"return_result_explicit":false,"code":85},{"name":"provideSubscriberLocation","module":"MAP-LocationServiceOperations","sha256":"280414f331b25e83c672dc7ce1773e9e4f1585f1d0f3f374bd98637e11ad6b0a","argument":"ProvideSubscriberLocation-Arg","result":"ProvideSubscriberLocation-Res","errors":["systemFailure","dataMissing","unexpectedDataValue","facilityNotSupported","unidentifiedSubscriber","illegalSubscriber","illegalEquipment","absentSubscriber","unauthorizedRequestingNetwork","unauthorizedLCSClient","positionMethodFailure"],"linked":[],"return_result":true,"return_result_explicit":false,"code":83},{"name":"subscriberLocationReport","module":"MAP-LocationServiceOperations","sha256":"280414f331b25e83c672dc7ce1773e9e4f1585f1d0f3f374bd98637e11ad6b0a","argument":"SubscriberLocationReport-Arg","result":"SubscriberLocationReport-Res","errors":["systemFailure","dataMissing","resourceLimitation","unexpectedDataValue","unknownSubscriber","unauthorizedRequestingNetwork","unknownOrUnreachableLCSClient"],"linked":[],"return_result":true,"return_result_explicit":false,"code":86},{"name":"updateLocation","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"UpdateLocationArg","result":"UpdateLocationRes","errors":["systemFailure","dataMissing","unexpectedDataValue","unknownSubscriber","roamingNotAllowed"],"linked":[],"return_result":true,"return_result_explicit":false,"code":2},{"name":"cancelLocation","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"CancelLocationArg","result":"CancelLocationRes","errors":["dataMissing","unexpectedDataValue"],"linked":[],"return_result":true,"return_result_explicit":false,"code":3},{"name":"purgeMS","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"PurgeMS-Arg","result":"PurgeMS-Res","errors":["dataMissing","unexpectedDataValue","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":67},{"name":"sendIdentification","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"SendIdentificationArg","result":"SendIdentificationRes","errors":["dataMissing","unidentifiedSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":55},{"name":"updateGprsLocation","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"UpdateGprsLocationArg","result":"UpdateGprsLocationRes","errors":["systemFailure","unexpectedDataValue","unknownSubscriber","roamingNotAllowed"],"linked":[],"return_result":true,"return_result_explicit":false,"code":23},{"name":"provideSubscriberInfo","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"ProvideSubscriberInfoArg","result":"ProvideSubscriberInfoRes","errors":["dataMissing","unexpectedDataValue"],"linked":[],"return_result":true,"return_result_explicit":false,"code":70},{"name":"anyTimeInterrogation","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"AnyTimeInterrogationArg","result":"AnyTimeInterrogationRes","errors":["systemFailure","ati-NotAllowed","dataMissing","unexpectedDataValue","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":71},{"name":"anyTimeSubscriptionInterrogation","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"AnyTimeSubscriptionInterrogationArg","result":"AnyTimeSubscriptionInterrogationRes","errors":["atsi-NotAllowed","dataMissing","unexpectedDataValue","unknownSubscriber","bearerServiceNotProvisioned","teleserviceNotProvisioned","callBarred","illegalSS-Operation","ss-NotAvailable","informationNotAvailable"],"linked":[],"return_result":true,"return_result_explicit":false,"code":62},{"name":"anyTimeModification","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"AnyTimeModificationArg","result":"AnyTimeModificationRes","errors":["atm-NotAllowed","dataMissing","unexpectedDataValue","unknownSubscriber","bearerServiceNotProvisioned","teleserviceNotProvisioned","callBarred","illegalSS-Operation","ss-SubscriptionViolation","ss-ErrorStatus","ss-Incompatibility","informationNotAvailable"],"linked":[],"return_result":true,"return_result_explicit":false,"code":65},{"name":"noteSubscriberDataModified","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"NoteSubscriberDataModifiedArg","result":"NoteSubscriberDataModifiedRes","errors":["dataMissing","unexpectedDataValue","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":5},{"name":"prepareHandover","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"PrepareHO-Arg","result":"PrepareHO-Res","errors":["systemFailure","dataMissing","unexpectedDataValue","noHandoverNumberAvailable","targetCellOutsideGroupCallArea"],"linked":[],"return_result":true,"return_result_explicit":false,"code":68},{"name":"sendEndSignal","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"SendEndSignal-Arg","result":"SendEndSignal-Res","errors":[],"linked":[],"return_result":true,"return_result_explicit":false,"code":29},{"name":"processAccessSignalling","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"ProcessAccessSignalling-Arg","errors":[],"linked":[],"return_result":true,"return_result_explicit":false,"code":33},{"name":"forwardAccessSignalling","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"ForwardAccessSignalling-Arg","errors":[],"linked":[],"return_result":true,"return_result_explicit":false,"code":34},{"name":"prepareSubsequentHandover","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"PrepareSubsequentHO-Arg","result":"PrepareSubsequentHO-Res","errors":["unexpectedDataValue","dataMissing","unknownMSC","subsequentHandoverFailure"],"linked":[],"return_result":true,"return_result_explicit":false,"code":69},{"name":"sendAuthenticationInfo","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"SendAuthenticationInfoArg","result":"SendAuthenticationInfoRes","errors":["systemFailure","dataMissing","unexpectedDataValue","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":56},{"name":"authenticationFailureReport","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"AuthenticationFailureReportArg","result":"AuthenticationFailureReportRes","errors":["systemFailure","unexpectedDataValue","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":15},{"name":"checkIMEI","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"CheckIMEI-Arg","result":"CheckIMEI-Res","errors":["systemFailure","dataMissing","unknownEquipment"],"linked":[],"return_result":true,"return_result_explicit":false,"code":43},{"name":"insertSubscriberData","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"InsertSubscriberDataArg","result":"InsertSubscriberDataRes","errors":["dataMissing","unexpectedDataValue","unidentifiedSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":7},{"name":"deleteSubscriberData","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"DeleteSubscriberDataArg","result":"DeleteSubscriberDataRes","errors":["dataMissing","unexpectedDataValue","unidentifiedSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":8},{"name":"reset","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"ResetArg","errors":[],"linked":[],"return_result":true,"return_result_explicit":false,"code":37},{"name":"forwardCheckSS-Indication","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","errors":[],"linked":[],"return_result":true,"return_result_explicit":false,"code":38},{"name":"restoreData","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"RestoreDataArg","result":"RestoreDataRes","errors":["systemFailure","dataMissing","unexpectedDataValue","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":57},{"name":"sendRoutingInfoForGprs","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"SendRoutingInfoForGprsArg","result":"SendRoutingInfoForGprsRes","errors":["absentSubscriber","systemFailure","dataMissing","unexpectedDataValue","unknownSubscriber","callBarred"],"linked":[],"return_result":true,"return_result_explicit":false,"code":24},{"name":"failureReport","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"FailureReportArg","result":"FailureReportRes","errors":["systemFailure","dataMissing","unexpectedDataValue","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":25},{"name":"noteMsPresentForGprs","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"NoteMsPresentForGprsArg","result":"NoteMsPresentForGprsRes","errors":["systemFailure","dataMissing","unexpectedDataValue","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":26},{"name":"noteMM-Event","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"NoteMM-EventArg","result":"NoteMM-EventRes","errors":["dataMissing","unexpectedDataValue","unknownSubscriber","mm-EventNotSupported"],"linked":[],"return_result":true,"return_result_explicit":false,"code":89},{"name":"updateVcsgLocation","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"UpdateVcsgLocationArg","result":"UpdateVcsgLocationRes","errors":["systemFailure","unexpectedDataValue","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":53},{"name":"cancelVcsgLocation","module":"MAP-MobileServiceOperations","sha256":"1ff741e4cfa8e39efd9585cd08d7c5196d14b483dc2776ebc4e8c6e07babc496","argument":"CancelVcsgLocationArg","result":"CancelVcsgLocationRes","errors":["dataMissing","unexpectedDataValue"],"linked":[],"return_result":true,"return_result_explicit":false,"code":36},{"name":"activateTraceMode","module":"MAP-OperationAndMaintenanceOperations","sha256":"7f706f72645f72d54c8add36cc083c7d20ccbc42f5bdbae5e3cfaf765e369845","argument":"ActivateTraceModeArg","result":"ActivateTraceModeRes","errors":["systemFailure","dataMissing","unexpectedDataValue","facilityNotSupported","unidentifiedSubscriber","tracingBufferFull"],"linked":[],"return_result":true,"return_result_explicit":false,"code":50},{"name":"deactivateTraceMode","module":"MAP-OperationAndMaintenanceOperations","sha256":"7f706f72645f72d54c8add36cc083c7d20ccbc42f5bdbae5e3cfaf765e369845","argument":"DeactivateTraceModeArg","result":"DeactivateTraceModeRes","errors":["systemFailure","dataMissing","unexpectedDataValue","facilityNotSupported","unidentifiedSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":51},{"name":"sendIMSI","module":"MAP-OperationAndMaintenanceOperations","sha256":"7f706f72645f72d54c8add36cc083c7d20ccbc42f5bdbae5e3cfaf765e369845","argument":"ISDN-AddressString","result":"IMSI","errors":["dataMissing","unexpectedDataValue","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":58},{"name":"sendRoutingInfoForSM","module":"MAP-ShortMessageServiceOperations","sha256":"6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb","argument":"RoutingInfoForSM-Arg","result":"RoutingInfoForSM-Res","errors":["systemFailure","dataMissing","unexpectedDataValue","facilityNotSupported","unknownSubscriber","teleserviceNotProvisioned","callBarred","absentSubscriberSM"],"linked":[],"return_result":true,"return_result_explicit":false,"code":45},{"name":"mo-ForwardSM","module":"MAP-ShortMessageServiceOperations","sha256":"6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb","argument":"MO-ForwardSM-Arg","result":"MO-ForwardSM-Res","errors":["systemFailure","unexpectedDataValue","facilityNotSupported","sm-DeliveryFailure"],"linked":[],"return_result":true,"return_result_explicit":false,"code":46},{"name":"mt-ForwardSM","module":"MAP-ShortMessageServiceOperations","sha256":"6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb","argument":"MT-ForwardSM-Arg","result":"MT-ForwardSM-Res","errors":["systemFailure","dataMissing","unexpectedDataValue","facilityNotSupported","unidentifiedSubscriber","illegalSubscriber","illegalEquipment","subscriberBusyForMT-SMS","sm-DeliveryFailure","absentSubscriberSM"],"linked":[],"return_result":true,"return_result_explicit":false,"code":44},{"name":"reportSM-DeliveryStatus","module":"MAP-ShortMessageServiceOperations","sha256":"6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb","argument":"ReportSM-DeliveryStatusArg","result":"ReportSM-DeliveryStatusRes","errors":["dataMissing","unexpectedDataValue","unknownSubscriber","messageWaitingListFull"],"linked":[],"return_result":true,"return_result_explicit":false,"code":47},{"name":"alertServiceCentre","module":"MAP-ShortMessageServiceOperations","sha256":"6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb","argument":"AlertServiceCentreArg","errors":["systemFailure","dataMissing","unexpectedDataValue"],"linked":[],"return_result":true,"return_result_explicit":true,"code":64},{"name":"informServiceCentre","module":"MAP-ShortMessageServiceOperations","sha256":"6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb","argument":"InformServiceCentreArg","errors":[],"linked":[],"return_result":true,"return_result_explicit":false,"code":63},{"name":"readyForSM","module":"MAP-ShortMessageServiceOperations","sha256":"6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb","argument":"ReadyForSM-Arg","result":"ReadyForSM-Res","errors":["dataMissing","unexpectedDataValue","facilityNotSupported","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":66},{"name":"mt-ForwardSM-VGCS","module":"MAP-ShortMessageServiceOperations","sha256":"6c8edebb3afbfa8e662db4adfd2da590323343c6df8c82f686761e779ed297bb","argument":"MT-ForwardSM-VGCS-Arg","result":"MT-ForwardSM-VGCS-Res","errors":["systemFailure","unexpectedDataValue"],"linked":[],"return_result":true,"return_result_explicit":false,"code":21},{"name":"registerSS","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"RegisterSS-Arg","result":"SS-Info","errors":["systemFailure","dataMissing","unexpectedDataValue","bearerServiceNotProvisioned","teleserviceNotProvisioned","callBarred","illegalSS-Operation","ss-ErrorStatus","ss-Incompatibility"],"linked":[],"return_result":true,"return_result_explicit":false,"code":10},{"name":"eraseSS","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"SS-ForBS-Code","result":"SS-Info","errors":["systemFailure","dataMissing","unexpectedDataValue","bearerServiceNotProvisioned","teleserviceNotProvisioned","callBarred","illegalSS-Operation","ss-ErrorStatus"],"linked":[],"return_result":true,"return_result_explicit":false,"code":11},{"name":"activateSS","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"SS-ForBS-Code","result":"SS-Info","errors":["systemFailure","dataMissing","unexpectedDataValue","bearerServiceNotProvisioned","teleserviceNotProvisioned","callBarred","illegalSS-Operation","ss-ErrorStatus","ss-SubscriptionViolation","ss-Incompatibility","negativePW-Check","numberOfPW-AttemptsViolation"],"linked":[],"return_result":true,"return_result_explicit":false,"code":12},{"name":"deactivateSS","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"SS-ForBS-Code","result":"SS-Info","errors":["systemFailure","dataMissing","unexpectedDataValue","bearerServiceNotProvisioned","teleserviceNotProvisioned","callBarred","illegalSS-Operation","ss-ErrorStatus","ss-SubscriptionViolation","negativePW-Check","numberOfPW-AttemptsViolation"],"linked":[],"return_result":true,"return_result_explicit":false,"code":13},{"name":"interrogateSS","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"SS-ForBS-Code","result":"InterrogateSS-Res","errors":["systemFailure","dataMissing","unexpectedDataValue","bearerServiceNotProvisioned","teleserviceNotProvisioned","callBarred","illegalSS-Operation","ss-NotAvailable"],"linked":[],"return_result":true,"return_result_explicit":false,"code":14},{"name":"processUnstructuredSS-Request","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"USSD-Arg","result":"USSD-Res","errors":["systemFailure","dataMissing","unexpectedDataValue","unknownAlphabet","callBarred"],"linked":[],"return_result":true,"return_result_explicit":false,"code":59},{"name":"unstructuredSS-Request","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"USSD-Arg","result":"USSD-Res","errors":["systemFailure","dataMissing","unexpectedDataValue","absentSubscriber","illegalSubscriber","illegalEquipment","unknownAlphabet","ussd-Busy"],"linked":[],"return_result":true,"return_result_explicit":false,"code":60},{"name":"unstructuredSS-Notify","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"USSD-Arg","errors":["systemFailure","dataMissing","unexpectedDataValue","absentSubscriber","illegalSubscriber","illegalEquipment","unknownAlphabet","ussd-Busy"],"linked":[],"return_result":true,"return_result_explicit":true,"code":61},{"name":"registerPassword","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"SS-Code","result":"Password","errors":["systemFailure","dataMissing","unexpectedDataValue","callBarred","ss-SubscriptionViolation","pw-RegistrationFailure","negativePW-Check","numberOfPW-AttemptsViolation"],"linked":["getPassword"],"return_result":true,"return_result_explicit":false,"code":17},{"name":"getPassword","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"GuidanceInfo","result":"Password","errors":[],"linked":[],"return_result":true,"return_result_explicit":false,"code":18},{"name":"ss-InvocationNotification","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"SS-InvocationNotificationArg","result":"SS-InvocationNotificationRes","errors":["dataMissing","unexpectedDataValue","unknownSubscriber"],"linked":[],"return_result":true,"return_result_explicit":false,"code":72},{"name":"registerCC-Entry","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"RegisterCC-EntryArg","result":"RegisterCC-EntryRes","errors":["systemFailure","dataMissing","unexpectedDataValue","callBarred","illegalSS-Operation","ss-ErrorStatus","ss-Incompatibility","shortTermDenial","longTermDenial","facilityNotSupported"],"linked":[],"return_result":true,"return_result_explicit":false,"code":76},{"name":"eraseCC-Entry","module":"MAP-SupplementaryServiceOperations","sha256":"b7a0e89547f549f31436610aca8c22b3889ec8e7d8da2928cc0e9c0c392d4982","argument":"EraseCC-EntryArg","result":"EraseCC-EntryRes","errors":["systemFailure","dataMissing","unexpectedDataValue","callBarred","illegalSS-Operation","ss-ErrorStatus"],"linked":[],"return_result":true,"return_result_explicit":false,"code":77}]`)
	if len(Operations()) != 70 || len(Errors()) != 56 {
		t.Fatal("catalogue cardinality")
	}
	for _, row := range rows {
		info, ok := LookupOperation(MAPOperationCode(row.Code))
		if !ok || info.Name != row.Name {
			t.Fatalf("missing %+v: %+v", row, info)
		}
		checkBindingSource(t, info.Source, row)
		checkBindingType(t, info.Argument, row.Argument)
		checkBindingType(t, info.Result, row.Result)
		if info.ReturnResult != row.ReturnResult || info.ReturnResultExplicit != row.ReturnResultExplicit || info.ArgumentOptional != nil || info.ResultOptional != nil {
			t.Fatalf("object flags %+v", info)
		}
		var names []string
		for _, e := range info.Errors {
			names = append(names, e.Name)
		}
		if !reflect.DeepEqual(names, row.Errors) && !(len(names) == 0 && len(row.Errors) == 0) {
			t.Fatalf("%s ERRORS %v want %v", row.Name, names, row.Errors)
		}
		if len(info.Linked) != len(row.Linked) {
			t.Fatalf("%s LINKED %v", row.Name, info.Linked)
		}
		if len(row.Linked) == 1 && info.Linked[0] != GetPassword {
			t.Fatal(info.Linked)
		}
	}
	for _, row := range bindingRows(t, `[{"name":"systemFailure","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SystemFailureParam","errors":[],"linked":[],"code":34},{"name":"dataMissing","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"DataMissingParam","errors":[],"linked":[],"code":35},{"name":"unexpectedDataValue","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnexpectedDataParam","errors":[],"linked":[],"code":36},{"name":"facilityNotSupported","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"FacilityNotSupParam","errors":[],"linked":[],"code":21},{"name":"incompatibleTerminal","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"IncompatibleTerminalParam","errors":[],"linked":[],"code":28},{"name":"resourceLimitation","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ResourceLimitationParam","errors":[],"linked":[],"code":51},{"name":"unknownSubscriber","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnknownSubscriberParam","errors":[],"linked":[],"code":1},{"name":"numberChanged","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"NumberChangedParam","errors":[],"linked":[],"code":44},{"name":"unknownMSC","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":3},{"name":"unidentifiedSubscriber","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnidentifiedSubParam","errors":[],"linked":[],"code":5},{"name":"unknownEquipment","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":7},{"name":"roamingNotAllowed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"RoamingNotAllowedParam","errors":[],"linked":[],"code":8},{"name":"illegalSubscriber","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"IllegalSubscriberParam","errors":[],"linked":[],"code":9},{"name":"illegalEquipment","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"IllegalEquipmentParam","errors":[],"linked":[],"code":12},{"name":"bearerServiceNotProvisioned","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"BearerServNotProvParam","errors":[],"linked":[],"code":10},{"name":"teleserviceNotProvisioned","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"TeleservNotProvParam","errors":[],"linked":[],"code":11},{"name":"noHandoverNumberAvailable","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":25},{"name":"subsequentHandoverFailure","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":26},{"name":"targetCellOutsideGroupCallArea","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"TargetCellOutsideGCA-Param","errors":[],"linked":[],"code":42},{"name":"tracingBufferFull","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"TracingBufferFullParam","errors":[],"linked":[],"code":40},{"name":"noRoamingNumberAvailable","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"NoRoamingNbParam","errors":[],"linked":[],"code":39},{"name":"absentSubscriber","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"AbsentSubscriberParam","errors":[],"linked":[],"code":27},{"name":"busySubscriber","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"BusySubscriberParam","errors":[],"linked":[],"code":45},{"name":"noSubscriberReply","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"NoSubscriberReplyParam","errors":[],"linked":[],"code":46},{"name":"callBarred","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"CallBarredParam","errors":[],"linked":[],"code":13},{"name":"forwardingViolation","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ForwardingViolationParam","errors":[],"linked":[],"code":14},{"name":"forwardingFailed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ForwardingFailedParam","errors":[],"linked":[],"code":47},{"name":"cug-Reject","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"CUG-RejectParam","errors":[],"linked":[],"code":15},{"name":"or-NotAllowed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"OR-NotAllowedParam","errors":[],"linked":[],"code":48},{"name":"ati-NotAllowed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ATI-NotAllowedParam","errors":[],"linked":[],"code":49},{"name":"atsi-NotAllowed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ATSI-NotAllowedParam","errors":[],"linked":[],"code":60},{"name":"atm-NotAllowed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ATM-NotAllowedParam","errors":[],"linked":[],"code":61},{"name":"informationNotAvailable","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"InformationNotAvailableParam","errors":[],"linked":[],"code":62},{"name":"illegalSS-Operation","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"IllegalSS-OperationParam","errors":[],"linked":[],"code":16},{"name":"ss-ErrorStatus","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SS-Status","errors":[],"linked":[],"code":17},{"name":"ss-NotAvailable","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SS-NotAvailableParam","errors":[],"linked":[],"code":18},{"name":"ss-SubscriptionViolation","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SS-SubscriptionViolationParam","errors":[],"linked":[],"code":19},{"name":"ss-Incompatibility","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SS-IncompatibilityCause","errors":[],"linked":[],"code":20},{"name":"unknownAlphabet","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":71},{"name":"ussd-Busy","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":72},{"name":"pw-RegistrationFailure","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"PW-RegistrationFailureCause","errors":[],"linked":[],"code":37},{"name":"negativePW-Check","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":38},{"name":"numberOfPW-AttemptsViolation","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":43},{"name":"shortTermDenial","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ShortTermDenialParam","errors":[],"linked":[],"code":29},{"name":"longTermDenial","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"LongTermDenialParam","errors":[],"linked":[],"code":30},{"name":"subscriberBusyForMT-SMS","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SubBusyForMT-SMS-Param","errors":[],"linked":[],"code":31},{"name":"sm-DeliveryFailure","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SM-DeliveryFailureCause","errors":[],"linked":[],"code":32},{"name":"messageWaitingListFull","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"MessageWaitListFullParam","errors":[],"linked":[],"code":33},{"name":"absentSubscriberSM","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"AbsentSubscriberSM-Param","errors":[],"linked":[],"code":6},{"name":"noGroupCallNumberAvailable","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"NoGroupCallNbParam","errors":[],"linked":[],"code":50},{"name":"ongoingGroupCall","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"OngoingGroupCallParam","errors":[],"linked":[],"code":22},{"name":"unauthorizedRequestingNetwork","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnauthorizedRequestingNetwork-Param","errors":[],"linked":[],"code":52},{"name":"unauthorizedLCSClient","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnauthorizedLCSClient-Param","errors":[],"linked":[],"code":53},{"name":"positionMethodFailure","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"PositionMethodFailure-Param","errors":[],"linked":[],"code":54},{"name":"unknownOrUnreachableLCSClient","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnknownOrUnreachableLCSClient-Param","errors":[],"linked":[],"code":58},{"name":"mm-EventNotSupported","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"MM-EventNotSupported-Param","errors":[],"linked":[],"code":59}]`) {
		info, ok := LookupError(MAPErrorCode(row.Code))
		if !ok || info.Name != row.Name {
			t.Fatalf("missing error %+v", row)
		}
		checkBindingSource(t, info.Source, row)
		checkBindingType(t, info.Parameter, row.Parameter)
		if info.ParameterOptional != nil {
			t.Fatal("comment-derived optionality")
		}
	}
	if _, ok := LookupOperation(-1); ok {
		t.Fatal("unknown operation")
	}
	if _, ok := LookupError(-1); ok {
		t.Fatal("unknown error")
	}
}
func TestCompleteSSDescriptorCatalogue(t *testing.T) {
	if len(SSOperations()) != 31 || len(SSErrors()) != 9 {
		t.Fatal("SS cardinality")
	}
	for _, row := range bindingRows(t, `[{"name":"processUnstructuredSS-Data","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"SS-UserData","result":"SS-UserData","code":19,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"notifySS","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"NotifySS-Arg","code":16,"errors":[],"linked":[],"error_bindings":[]},{"name":"forwardChargeAdvice","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"ForwardChargeAdviceArg","code":125,"errors":[],"linked":[],"error_bindings":[]},{"name":"forwardCUG-Info","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"ForwardCUG-InfoArg","code":120,"errors":[],"linked":[],"error_bindings":[]},{"name":"buildMPTY","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","code":124,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-NotAvailable","ss-Incompatibility","systemFailure","resourcesNotAvailable","maxNumberOfMPTY-ParticipantsExceeded"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-NotAvailable","kind":"ERROR","module":"MAP-Errors","line":384,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-NotAvailableParam","code":18,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsNotAvailable","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSNotAvailableParam"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"resourcesNotAvailable","kind":"ERROR","module":"SS-Errors","line":26,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":127,"errors":[],"linked":[],"constant":"SSResourcesNotAvailable","code_type":"SSErrorCode"},{"name":"maxNumberOfMPTY-ParticipantsExceeded","kind":"ERROR","module":"SS-Errors","line":28,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":126,"errors":[],"linked":[],"constant":"SSMaxNumberOfMPTYParticipantsExceeded","code_type":"SSErrorCode"}]},{"name":"holdMPTY","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","code":123,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-Incompatibility","facilityNotSupported","systemFailure"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"}]},{"name":"retrieveMPTY","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","code":122,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-Incompatibility","facilityNotSupported","systemFailure"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"}]},{"name":"splitMPTY","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","code":121,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-Incompatibility","facilityNotSupported","systemFailure"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"}]},{"name":"explicitCT","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","code":126,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-NotAvailable","ss-Incompatibility","facilityNotSupported","systemFailure","resourcesNotAvailable","callBarred"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-NotAvailable","kind":"ERROR","module":"MAP-Errors","line":384,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-NotAvailableParam","code":18,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsNotAvailable","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSNotAvailableParam"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"resourcesNotAvailable","kind":"ERROR","module":"SS-Errors","line":26,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":127,"errors":[],"linked":[],"constant":"SSResourcesNotAvailable","code_type":"SSErrorCode"},{"name":"callBarred","kind":"ERROR","module":"MAP-Errors","line":313,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"CallBarredParam","code":13,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsCallBarred","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERCallBarredParam"}]},{"name":"accessRegisterCCEntry","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"AccessRegisterCCEntryArg","result":"RegisterCC-EntryRes","code":119,"errors":["systemFailure","dataMissing","unexpectedDataValue","callBarred","illegalSS-Operation","ss-ErrorStatus","ss-Incompatibility","shortTermDenial","longTermDenial","facilityNotSupported"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"callBarred","kind":"ERROR","module":"MAP-Errors","line":313,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"CallBarredParam","code":13,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsCallBarred","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERCallBarredParam"},{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"shortTermDenial","kind":"ERROR","module":"MAP-Errors","line":421,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"ShortTermDenialParam","code":29,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsShortTermDenial","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERShortTermDenialParam"},{"name":"longTermDenial","kind":"ERROR","module":"MAP-Errors","line":427,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"LongTermDenialParam","code":30,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsLongTermDenial","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERLongTermDenialParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"}]},{"name":"callDeflection","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"CallDeflectionArg","code":117,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-NotAvailable","ss-Incompatibility","facilityNotSupported","systemFailure","resourcesNotAvailable","forwardingViolation","callBarred","deflectionToServedSubscriber","invalidDeflectedToNumber","specialServiceCode","forwardingFailed"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-NotAvailable","kind":"ERROR","module":"MAP-Errors","line":384,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-NotAvailableParam","code":18,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsNotAvailable","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSNotAvailableParam"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"resourcesNotAvailable","kind":"ERROR","module":"SS-Errors","line":26,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":127,"errors":[],"linked":[],"constant":"SSResourcesNotAvailable","code_type":"SSErrorCode"},{"name":"forwardingViolation","kind":"ERROR","module":"MAP-Errors","line":319,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"ForwardingViolationParam","code":14,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsForwardingViolation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERForwardingViolationParam"},{"name":"callBarred","kind":"ERROR","module":"MAP-Errors","line":313,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"CallBarredParam","code":13,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsCallBarred","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERCallBarredParam"},{"name":"deflectionToServedSubscriber","kind":"ERROR","module":"SS-Errors","line":34,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":123,"errors":[],"linked":[],"constant":"SSDeflectionToServedSubscriber","code_type":"SSErrorCode"},{"name":"invalidDeflectedToNumber","kind":"ERROR","module":"SS-Errors","line":30,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":125,"errors":[],"linked":[],"constant":"SSInvalidDeflectedToNumber","code_type":"SSErrorCode"},{"name":"specialServiceCode","kind":"ERROR","module":"SS-Errors","line":32,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":124,"errors":[],"linked":[],"constant":"SSSpecialServiceCode","code_type":"SSErrorCode"},{"name":"forwardingFailed","kind":"ERROR","module":"MAP-Errors","line":325,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"ForwardingFailedParam","code":47,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsForwardingFailed","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERForwardingFailedParam"}]},{"name":"userUserService","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"UserUserServiceArg","code":118,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-NotAvailable","ss-Incompatibility","facilityNotSupported","systemFailure","resourcesNotAvailable","rejectedByNetwork","rejectedByUser"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-NotAvailable","kind":"ERROR","module":"MAP-Errors","line":384,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-NotAvailableParam","code":18,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsNotAvailable","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSNotAvailableParam"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"resourcesNotAvailable","kind":"ERROR","module":"SS-Errors","line":26,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":127,"errors":[],"linked":[],"constant":"SSResourcesNotAvailable","code_type":"SSErrorCode"},{"name":"rejectedByNetwork","kind":"ERROR","module":"SS-Errors","line":36,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":122,"errors":[],"linked":[],"constant":"SSRejectedByNetwork","code_type":"SSErrorCode"},{"name":"rejectedByUser","kind":"ERROR","module":"SS-Errors","line":38,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":121,"errors":[],"linked":[],"constant":"SSRejectedByUser","code_type":"SSErrorCode"}]},{"name":"lcs-LocationNotification","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LocationNotificationArg","result":"LocationNotificationRes","code":116,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-MOLR","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-MOLRArg","result":"LCS-MOLRRes","code":115,"errors":["systemFailure","unexpectedDataValue","dataMissing","facilityNotSupported","ss-SubscriptionViolation","positionMethodFailure"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"ss-SubscriptionViolation","kind":"ERROR","module":"MAP-Errors","line":391,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-SubscriptionViolationParam","code":19,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsSubscriptionViolation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSSubscriptionViolationParam"},{"name":"positionMethodFailure","kind":"ERROR","module":"MAP-Errors","line":486,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"PositionMethodFailure-Param","code":54,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsPositionMethodFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERPositionMethodFailureParam"}]},{"name":"lcs-AreaEventRequest","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-AreaEventRequestArg","code":114,"errors":["systemFailure","facilityNotSupported","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-AreaEventReport","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-AreaEventReportArg","code":113,"errors":["systemFailure","unexpectedDataValue","facilityNotSupported"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"}]},{"name":"lcs-AreaEventCancellation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-AreaEventCancellationArg","code":112,"errors":["systemFailure","facilityNotSupported","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-PeriodicLocationRequest","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-PeriodicLocationRequestArg","result":"LCS-PeriodicLocationRequestRes","code":111,"errors":["systemFailure","facilityNotSupported","unexpectedDataValue","dataMissing"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"}]},{"name":"lcs-LocationUpdate","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-LocationUpdateArg","result":"LCS-LocationUpdateRes","code":110,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-PeriodicLocationCancellation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-PeriodicLocationCancellationArg","code":109,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-PeriodicTriggeredInvoke","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-PeriodicTriggeredInvokeArg","result":"LCS-PeriodicTriggeredInvokeRes","code":108,"errors":["systemFailure","facilityNotSupported","unexpectedDataValue","dataMissing","resourceLimitation"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"resourceLimitation","kind":"ERROR","module":"MAP-Errors","line":195,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"ResourceLimitationParam","code":51,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsResourceLimitation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERResourceLimitationParam"}]},{"name":"lcs-EventReport","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-EventReportArg","result":"LCS-EventReportRes","code":107,"errors":["systemFailure","facilityNotSupported","ss-SubscriptionViolation","unexpectedDataValue","dataMissing","resourceLimitation"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"ss-SubscriptionViolation","kind":"ERROR","module":"MAP-Errors","line":391,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-SubscriptionViolationParam","code":19,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsSubscriptionViolation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSSubscriptionViolationParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"resourceLimitation","kind":"ERROR","module":"MAP-Errors","line":195,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"ResourceLimitationParam","code":51,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsResourceLimitation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERResourceLimitationParam"}]},{"name":"lcs-CancelDeferredLocation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-CancelDeferredLocationArg","code":106,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-MSCancelDeferredLocation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-CancelDeferredLocationArg","code":105,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-LocationPrivacySetting","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-LocationPrivacySettingArg","code":104,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-PruAssociation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-PruAssociationArg","result":"LCS-PruAssociationRes","code":103,"errors":["lcs-invalidPru","lcs-PruAssociationRej","systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"lcs-invalidPru","kind":"ERROR","module":"SS-Errors","line":40,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":120,"errors":[],"linked":[],"constant":"SSLcsInvalidPru","code_type":"SSErrorCode"},{"name":"lcs-PruAssociationRej","kind":"ERROR","module":"SS-Errors","line":42,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","parameter":"PruAssociationRejParam","code":119,"errors":[],"linked":[],"constant":"SSLcsPruAssociationRej","code_type":"SSErrorCode","parameter_binding":"PruAssociationRejParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-PruDisassociation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-PruDisassociationArg","code":102,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-SLMOLR","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-SLMOLRArg","result":"LCS-SLMOLRRes","code":101,"errors":["systemFailure","unexpectedDataValue","dataMissing","facilityNotSupported","ss-SubscriptionViolation","positionMethodFailure"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"ss-SubscriptionViolation","kind":"ERROR","module":"MAP-Errors","line":391,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-SubscriptionViolationParam","code":19,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsSubscriptionViolation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSSubscriptionViolationParam"},{"name":"positionMethodFailure","kind":"ERROR","module":"MAP-Errors","line":486,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"PositionMethodFailure-Param","code":54,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsPositionMethodFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERPositionMethodFailureParam"}]},{"name":"lcs-SLMTLR","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-SLMTLRArg","result":"LCS-SLMTLRRes","code":100,"errors":["systemFailure","unexpectedDataValue","dataMissing","facilityNotSupported"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"}]},{"name":"lcs-DLRSPPTransport","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-DLRSPPTransportArg","result":"LCS-DLRSPPTransportRes","code":99,"errors":["systemFailure","facilityNotSupported"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"}]},{"name":"lcs-ULRSPPTransport","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-ULRSPPTransportArg","result":"LCS-ULRSPPTransportRes","code":98,"errors":["systemFailure","facilityNotSupported"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"}]}]`) {
		info, ok := LookupSSOperation(SSOperationCode(row.Code))
		if !ok || info.Name != row.Name {
			t.Fatalf("SS %+v", row)
		}
		checkBindingSource(t, info.Source, row)
		checkBindingType(t, info.Argument, row.Argument)
		checkBindingType(t, info.Result, row.Result)
		if !info.ReturnResult {
			t.Fatalf("X.880 default missing %s", row.Name)
		}
		if len(info.Errors) != len(row.ErrorBindings) {
			t.Fatalf("SS errors %s", row.Name)
		}
		for i, e := range info.Errors {
			expected := row.ErrorBindings[i]
			if e.Name != expected.Name || e.LocalCode != expected.Code || e.DeclaringModuleOID == "" {
				t.Fatalf("SS member %+v want %+v", e, expected)
			}
			checkBindingSource(t, e.Source, expected)
			checkBindingType(t, e.Parameter, expected.Parameter)
		}
	}
}
func TestApplicationContextCatalogue(t *testing.T) {
	contexts := ApplicationContexts()
	if len(contexts) != 44 {
		t.Fatal(len(contexts))
	}
	{
		oid := NetworkLocUpContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "networkLocUpContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := LocationCancellationContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "locationCancellationContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := RoamingNumberEnquiryContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "roamingNumberEnquiryContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := AuthenticationFailureReportContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "authenticationFailureReportContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := LocationInfoRetrievalContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "locationInfoRetrievalContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := ResetContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "resetContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := HandoverControlContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "handoverControlContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := EquipmentMngtContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "equipmentMngtContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := InfoRetrievalContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "infoRetrievalContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := InterVlrInfoRetrievalContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "interVlrInfoRetrievalContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := SubscriberDataMngtContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "subscriberDataMngtContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := TracingContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "tracingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := NetworkFunctionalSsContextV2()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 2 || c.Name != "networkFunctionalSsContext-v2" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := NetworkUnstructuredSsContextV2()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 2 || c.Name != "networkUnstructuredSsContext-v2" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := ShortMsgGatewayContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "shortMsgGatewayContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := ShortMsgMORelayContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "shortMsgMO-RelayContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := ShortMsgAlertContextV2()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 2 || c.Name != "shortMsgAlertContext-v2" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := MwdMngtContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "mwdMngtContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := ShortMsgMTRelayContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "shortMsgMT-RelayContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := ShortMsgMTRelayVGCSContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "shortMsgMT-Relay-VGCS-Context-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := ImsiRetrievalContextV2()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 2 || c.Name != "imsiRetrievalContext-v2" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := MsPurgingContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "msPurgingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := SubscriberInfoEnquiryContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "subscriberInfoEnquiryContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := AnyTimeInfoEnquiryContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "anyTimeInfoEnquiryContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := CallControlTransferContextV4()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 4 || c.Name != "callControlTransferContext-v4" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := SsInvocationNotificationContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "ss-InvocationNotificationContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := GroupCallControlContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "groupCallControlContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := GroupCallInfoRetrievalContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "groupCallInfoRetrievalContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := GprsLocationUpdateContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "gprsLocationUpdateContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := GprsLocationInfoRetrievalContextV4()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 4 || c.Name != "gprsLocationInfoRetrievalContext-v4" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := FailureReportContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "failureReportContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := GprsNotifyContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "gprsNotifyContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := ReportingContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "reportingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := CallCompletionContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "callCompletionContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := IstAlertingContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "istAlertingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := ServiceTerminationContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "serviceTerminationContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := LocationSvcGatewayContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "locationSvcGatewayContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := LocationSvcEnquiryContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "locationSvcEnquiryContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := MmEventReportingContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "mm-EventReportingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := AnyTimeInfoHandlingContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "anyTimeInfoHandlingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := SubscriberDataModificationNotificationContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "subscriberDataModificationNotificationContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := ResourceManagementContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "resourceManagementContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := VcsgLocationUpdateContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "vcsgLocationUpdateContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := VcsgLocationCancellationContextV3()
		c, ok := LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "vcsgLocationCancellationContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	if _, ok := LookupApplicationContext(MapAc()); ok {
		t.Fatal("root is not a context")
	}
}
func TestTypedDescriptorSnapshots(t *testing.T) {
	first := Operations()
	before, _ := LookupOperation(first[0].Code)
	first[0].Name = "changed"
	if first[0].Argument != nil {
		first[0].Argument.ASN1Name = "changed"
	}
	if len(first[0].Errors) > 0 {
		first[0].Errors[0].Name = "changed"
		if first[0].Errors[0].Parameter != nil {
			first[0].Errors[0].Parameter.ASN1Name = "changed"
		}
	}
	after, _ := LookupOperation(before.Code)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("shared operation metadata %+v %+v", before, after)
	}
	op := RegisterPasswordOperation()
	info := op.Info()
	info.Linked[0] = -1
	if op.Info().Linked[0] != GetPassword {
		t.Fatal("shared linked slice")
	}
	errors := Errors()
	prior, _ := LookupError(errors[0].Code)
	errors[0].Parameter.ASN1Name = "changed"
	again, _ := LookupError(prior.Code)
	if !reflect.DeepEqual(prior, again) {
		t.Fatal("shared error type ref")
	}
	ss := SSOperations()
	beforeSS, _ := LookupSSOperation(ss[0].Code)
	ss[0].Errors[0].Name = "changed"
	ss[0].Errors[0].Parameter.ASN1Name = "changed"
	afterSS, _ := LookupSSOperation(beforeSS.Code)
	if !reflect.DeepEqual(beforeSS, afterSS) {
		t.Fatal("shared SS metadata")
	}
	contexts := ApplicationContexts()
	oid := contexts[0].OID
	contexts[0].Name = "changed"
	context, _ := LookupApplicationContext(oid)
	if context.Name == "changed" {
		t.Fatal("shared context")
	}
}
func TestTypedErrorSelection(t *testing.T) {
	op := SendRoutingInfoForSMOperation()
	value := SendRoutingInfoForSMErrors{AbsentSubscriberSM: &ErrorValue[AbsentSubscriberSMParam]{Parameter: &AbsentSubscriberSMParam{}}}
	encoded, err := op.EncodeError(value)
	if err != nil || encoded.Code != AbsentSubscriberSM || !encoded.HasParameter {
		t.Fatalf("encode %+v %v", encoded, err)
	}
	decoded, err := op.DecodeError(encoded.Code, encoded.Parameter, encoded.HasParameter)
	if err != nil || decoded.AbsentSubscriberSM == nil || decoded.AbsentSubscriberSM.Parameter == nil {
		t.Fatalf("decode %+v %v", decoded, err)
	}
	if _, err := UpdateLocationOperation().DecodeError(encoded.Code, encoded.Parameter, true); err == nil {
		t.Fatal("disallowed error")
	}
	if _, err := op.EncodeError(SendRoutingInfoForSMErrors{}); err == nil {
		t.Fatal("zero arm")
	}
	value.SystemFailure = &ErrorValue[SystemFailureParam]{}
	if _, err := op.EncodeError(value); err == nil {
		t.Fatal("multiple arms")
	}
	if _, err := op.DecodeError(AbsentSubscriberSM, []byte{5, 0}, false); err == nil {
		t.Fatal("bytes on absent parameter")
	}
	if _, err := op.DecodeError(AbsentSubscriberSM, []byte{0x30, 0, 5, 0}, true); err == nil {
		t.Fatal("multiple TLVs")
	}
	absent, err := op.DecodeError(AbsentSubscriberSM, nil, false)
	if err != nil || absent.AbsentSubscriberSM == nil || absent.AbsentSubscriberSM.Parameter != nil {
		t.Fatalf("absence %+v %v", absent, err)
	}
	noArg, exists := ForwardCheckSSIndicationOperation().Argument()
	if exists {
		t.Fatal("manufactured argument")
	}
	if _, err := noArg.DecodeBER([]byte{5, 0}); err == nil {
		t.Fatal("NoParameter codec")
	}
	if _, err := SSNotifySSOperation().EncodeError(SSNotifySSErrors{}); err == nil {
		t.Fatal("zero arm operation")
	}
	plain := SSResourcesNotAvailableErrorDescriptor()
	if _, ok := plain.Parameter(); ok {
		t.Fatal("no PARAMETER is NULL")
	}
	ssop := SSProcessUnstructuredSSDataOperation()
	ssValue, err := ssop.DecodeError(34, nil, false)
	if err != nil || ssValue.SystemFailure == nil {
		t.Fatalf("SS mixed-origin absence %+v %v", ssValue, err)
	}
	if _, err := ssop.DecodeError(127, nil, false); err == nil {
		t.Fatal("SS unlisted member")
	}
	var zero Operation[NoParameter, NoParameter, SSNotifySSErrors]
	if _, err := zero.EncodeError(SSNotifySSErrors{}); err == nil {
		t.Fatal("zero descriptor")
	}
	primitive := SendIMSIOperation()
	argument, ok := primitive.Argument()
	if !ok {
		t.Fatal("primitive argument missing")
	}
	wire := []byte{4, 0x81, 1, 0x91}
	v, err := argument.DecodeBER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := argument.EncodeBER(v)
	if err != nil || !bytes.Equal(wire, replayed) {
		t.Fatalf("primitive replay %x %v", replayed, err)
	}
	var log ber.ViolationLog
	bad, err := IMSICodec().DecodeBER([]byte{4, 1, 1}, ber.WithTolerance(&log))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IMSICodec().EncodeDER(bad); err == nil {
		t.Fatal("tolerant DER")
	}
}

func TestContextValuesAgainstApprovedTable(t *testing.T) {
	{
		oid := MapAc()
		if oid.String() != "0.4.0.0.1.0" {
			t.Fatalf("OID MapAc: %s", oid.String())
		}
	}
	{
		oid := NetworkLocUpContextV3()
		if oid.String() != "0.4.0.0.1.0.1.3" {
			t.Fatalf("OID NetworkLocUpContextV3: %s", oid.String())
		}
	}
	{
		oid := LocationCancellationContextV3()
		if oid.String() != "0.4.0.0.1.0.2.3" {
			t.Fatalf("OID LocationCancellationContextV3: %s", oid.String())
		}
	}
	{
		oid := RoamingNumberEnquiryContextV3()
		if oid.String() != "0.4.0.0.1.0.3.3" {
			t.Fatalf("OID RoamingNumberEnquiryContextV3: %s", oid.String())
		}
	}
	{
		oid := AuthenticationFailureReportContextV3()
		if oid.String() != "0.4.0.0.1.0.39.3" {
			t.Fatalf("OID AuthenticationFailureReportContextV3: %s", oid.String())
		}
	}
	{
		oid := LocationInfoRetrievalContextV3()
		if oid.String() != "0.4.0.0.1.0.5.3" {
			t.Fatalf("OID LocationInfoRetrievalContextV3: %s", oid.String())
		}
	}
	{
		oid := ResetContextV3()
		if oid.String() != "0.4.0.0.1.0.10.3" {
			t.Fatalf("OID ResetContextV3: %s", oid.String())
		}
	}
	{
		oid := HandoverControlContextV3()
		if oid.String() != "0.4.0.0.1.0.11.3" {
			t.Fatalf("OID HandoverControlContextV3: %s", oid.String())
		}
	}
	{
		oid := EquipmentMngtContextV3()
		if oid.String() != "0.4.0.0.1.0.13.3" {
			t.Fatalf("OID EquipmentMngtContextV3: %s", oid.String())
		}
	}
	{
		oid := InfoRetrievalContextV3()
		if oid.String() != "0.4.0.0.1.0.14.3" {
			t.Fatalf("OID InfoRetrievalContextV3: %s", oid.String())
		}
	}
	{
		oid := InterVlrInfoRetrievalContextV3()
		if oid.String() != "0.4.0.0.1.0.15.3" {
			t.Fatalf("OID InterVlrInfoRetrievalContextV3: %s", oid.String())
		}
	}
	{
		oid := SubscriberDataMngtContextV3()
		if oid.String() != "0.4.0.0.1.0.16.3" {
			t.Fatalf("OID SubscriberDataMngtContextV3: %s", oid.String())
		}
	}
	{
		oid := TracingContextV3()
		if oid.String() != "0.4.0.0.1.0.17.3" {
			t.Fatalf("OID TracingContextV3: %s", oid.String())
		}
	}
	{
		oid := NetworkFunctionalSsContextV2()
		if oid.String() != "0.4.0.0.1.0.18.2" {
			t.Fatalf("OID NetworkFunctionalSsContextV2: %s", oid.String())
		}
	}
	{
		oid := NetworkUnstructuredSsContextV2()
		if oid.String() != "0.4.0.0.1.0.19.2" {
			t.Fatalf("OID NetworkUnstructuredSsContextV2: %s", oid.String())
		}
	}
	{
		oid := ShortMsgGatewayContextV3()
		if oid.String() != "0.4.0.0.1.0.20.3" {
			t.Fatalf("OID ShortMsgGatewayContextV3: %s", oid.String())
		}
	}
	{
		oid := ShortMsgMORelayContextV3()
		if oid.String() != "0.4.0.0.1.0.21.3" {
			t.Fatalf("OID ShortMsgMORelayContextV3: %s", oid.String())
		}
	}
	{
		oid := ShortMsgAlertContextV2()
		if oid.String() != "0.4.0.0.1.0.23.2" {
			t.Fatalf("OID ShortMsgAlertContextV2: %s", oid.String())
		}
	}
	{
		oid := MwdMngtContextV3()
		if oid.String() != "0.4.0.0.1.0.24.3" {
			t.Fatalf("OID MwdMngtContextV3: %s", oid.String())
		}
	}
	{
		oid := ShortMsgMTRelayContextV3()
		if oid.String() != "0.4.0.0.1.0.25.3" {
			t.Fatalf("OID ShortMsgMTRelayContextV3: %s", oid.String())
		}
	}
	{
		oid := ShortMsgMTRelayVGCSContextV3()
		if oid.String() != "0.4.0.0.1.0.41.3" {
			t.Fatalf("OID ShortMsgMTRelayVGCSContextV3: %s", oid.String())
		}
	}
	{
		oid := ImsiRetrievalContextV2()
		if oid.String() != "0.4.0.0.1.0.26.2" {
			t.Fatalf("OID ImsiRetrievalContextV2: %s", oid.String())
		}
	}
	{
		oid := MsPurgingContextV3()
		if oid.String() != "0.4.0.0.1.0.27.3" {
			t.Fatalf("OID MsPurgingContextV3: %s", oid.String())
		}
	}
	{
		oid := SubscriberInfoEnquiryContextV3()
		if oid.String() != "0.4.0.0.1.0.28.3" {
			t.Fatalf("OID SubscriberInfoEnquiryContextV3: %s", oid.String())
		}
	}
	{
		oid := AnyTimeInfoEnquiryContextV3()
		if oid.String() != "0.4.0.0.1.0.29.3" {
			t.Fatalf("OID AnyTimeInfoEnquiryContextV3: %s", oid.String())
		}
	}
	{
		oid := CallControlTransferContextV4()
		if oid.String() != "0.4.0.0.1.0.6.4" {
			t.Fatalf("OID CallControlTransferContextV4: %s", oid.String())
		}
	}
	{
		oid := SsInvocationNotificationContextV3()
		if oid.String() != "0.4.0.0.1.0.36.3" {
			t.Fatalf("OID SsInvocationNotificationContextV3: %s", oid.String())
		}
	}
	{
		oid := GroupCallControlContextV3()
		if oid.String() != "0.4.0.0.1.0.31.3" {
			t.Fatalf("OID GroupCallControlContextV3: %s", oid.String())
		}
	}
	{
		oid := GroupCallInfoRetrievalContextV3()
		if oid.String() != "0.4.0.0.1.0.45.3" {
			t.Fatalf("OID GroupCallInfoRetrievalContextV3: %s", oid.String())
		}
	}
	{
		oid := GprsLocationUpdateContextV3()
		if oid.String() != "0.4.0.0.1.0.32.3" {
			t.Fatalf("OID GprsLocationUpdateContextV3: %s", oid.String())
		}
	}
	{
		oid := GprsLocationInfoRetrievalContextV4()
		if oid.String() != "0.4.0.0.1.0.33.4" {
			t.Fatalf("OID GprsLocationInfoRetrievalContextV4: %s", oid.String())
		}
	}
	{
		oid := FailureReportContextV3()
		if oid.String() != "0.4.0.0.1.0.34.3" {
			t.Fatalf("OID FailureReportContextV3: %s", oid.String())
		}
	}
	{
		oid := GprsNotifyContextV3()
		if oid.String() != "0.4.0.0.1.0.35.3" {
			t.Fatalf("OID GprsNotifyContextV3: %s", oid.String())
		}
	}
	{
		oid := ReportingContextV3()
		if oid.String() != "0.4.0.0.1.0.7.3" {
			t.Fatalf("OID ReportingContextV3: %s", oid.String())
		}
	}
	{
		oid := CallCompletionContextV3()
		if oid.String() != "0.4.0.0.1.0.8.3" {
			t.Fatalf("OID CallCompletionContextV3: %s", oid.String())
		}
	}
	{
		oid := IstAlertingContextV3()
		if oid.String() != "0.4.0.0.1.0.4.3" {
			t.Fatalf("OID IstAlertingContextV3: %s", oid.String())
		}
	}
	{
		oid := ServiceTerminationContextV3()
		if oid.String() != "0.4.0.0.1.0.9.3" {
			t.Fatalf("OID ServiceTerminationContextV3: %s", oid.String())
		}
	}
	{
		oid := LocationSvcGatewayContextV3()
		if oid.String() != "0.4.0.0.1.0.37.3" {
			t.Fatalf("OID LocationSvcGatewayContextV3: %s", oid.String())
		}
	}
	{
		oid := LocationSvcEnquiryContextV3()
		if oid.String() != "0.4.0.0.1.0.38.3" {
			t.Fatalf("OID LocationSvcEnquiryContextV3: %s", oid.String())
		}
	}
	{
		oid := MmEventReportingContextV3()
		if oid.String() != "0.4.0.0.1.0.42.3" {
			t.Fatalf("OID MmEventReportingContextV3: %s", oid.String())
		}
	}
	{
		oid := AnyTimeInfoHandlingContextV3()
		if oid.String() != "0.4.0.0.1.0.43.3" {
			t.Fatalf("OID AnyTimeInfoHandlingContextV3: %s", oid.String())
		}
	}
	{
		oid := SubscriberDataModificationNotificationContextV3()
		if oid.String() != "0.4.0.0.1.0.22.3" {
			t.Fatalf("OID SubscriberDataModificationNotificationContextV3: %s", oid.String())
		}
	}
	{
		oid := ResourceManagementContextV3()
		if oid.String() != "0.4.0.0.1.0.44.3" {
			t.Fatalf("OID ResourceManagementContextV3: %s", oid.String())
		}
	}
	{
		oid := VcsgLocationUpdateContextV3()
		if oid.String() != "0.4.0.0.1.0.46.3" {
			t.Fatalf("OID VcsgLocationUpdateContextV3: %s", oid.String())
		}
	}
	{
		oid := VcsgLocationCancellationContextV3()
		if oid.String() != "0.4.0.0.1.0.47.3" {
			t.Fatalf("OID VcsgLocationCancellationContextV3: %s", oid.String())
		}
	}
}
func TestSupplementalErrorMetadataAgainstApprovedTables(t *testing.T) {
	if len(v21_map_errors.HistoricalMAPErrors()) != 56 {
		t.Fatal("historical error cardinality")
	}
	{
		info, ok := LookupSSError(SSErrorCode(127))
		if !ok || info.Name != "resourcesNotAvailable" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "resourcesNotAvailable" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := LookupSSError(SSErrorCode(126))
		if !ok || info.Name != "maxNumberOfMPTY-ParticipantsExceeded" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "maxNumberOfMPTY-ParticipantsExceeded" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := LookupSSError(SSErrorCode(125))
		if !ok || info.Name != "invalidDeflectedToNumber" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "invalidDeflectedToNumber" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := LookupSSError(SSErrorCode(124))
		if !ok || info.Name != "specialServiceCode" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "specialServiceCode" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := LookupSSError(SSErrorCode(123))
		if !ok || info.Name != "deflectionToServedSubscriber" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "deflectionToServedSubscriber" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := LookupSSError(SSErrorCode(122))
		if !ok || info.Name != "rejectedByNetwork" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "rejectedByNetwork" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := LookupSSError(SSErrorCode(121))
		if !ok || info.Name != "rejectedByUser" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "rejectedByUser" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := LookupSSError(SSErrorCode(120))
		if !ok || info.Name != "lcs-invalidPru" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "lcs-invalidPru" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := LookupSSError(SSErrorCode(119))
		if !ok || info.Name != "lcs-PruAssociationRej" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "lcs-PruAssociationRej" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "PruAssociationRejParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(34))
		if !ok || info.Name != "systemFailure" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "systemFailure" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "SystemFailureParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(35))
		if !ok || info.Name != "dataMissing" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "dataMissing" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "DataMissingParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(36))
		if !ok || info.Name != "unexpectedDataValue" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "unexpectedDataValue" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "UnexpectedDataParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(21))
		if !ok || info.Name != "facilityNotSupported" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "facilityNotSupported" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "FacilityNotSupParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(28))
		if !ok || info.Name != "incompatibleTerminal" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "incompatibleTerminal" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "IncompatibleTerminalParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(51))
		if !ok || info.Name != "resourceLimitation" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "resourceLimitation" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "ResourceLimitationParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(1))
		if !ok || info.Name != "unknownSubscriber" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "unknownSubscriber" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "UnknownSubscriberParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(44))
		if !ok || info.Name != "numberChanged" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "numberChanged" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "NumberChangedParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(3))
		if !ok || info.Name != "unknownMSC" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "unknownMSC" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(5))
		if !ok || info.Name != "unidentifiedSubscriber" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "unidentifiedSubscriber" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "UnidentifiedSubParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(7))
		if !ok || info.Name != "unknownEquipment" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "unknownEquipment" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(8))
		if !ok || info.Name != "roamingNotAllowed" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "roamingNotAllowed" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "RoamingNotAllowedParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(9))
		if !ok || info.Name != "illegalSubscriber" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "illegalSubscriber" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "IllegalSubscriberParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(12))
		if !ok || info.Name != "illegalEquipment" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "illegalEquipment" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "IllegalEquipmentParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(10))
		if !ok || info.Name != "bearerServiceNotProvisioned" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "bearerServiceNotProvisioned" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "BearerServNotProvParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(11))
		if !ok || info.Name != "teleserviceNotProvisioned" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "teleserviceNotProvisioned" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "TeleservNotProvParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(25))
		if !ok || info.Name != "noHandoverNumberAvailable" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "noHandoverNumberAvailable" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(26))
		if !ok || info.Name != "subsequentHandoverFailure" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "subsequentHandoverFailure" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(42))
		if !ok || info.Name != "targetCellOutsideGroupCallArea" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "targetCellOutsideGroupCallArea" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "TargetCellOutsideGCA-Param" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(40))
		if !ok || info.Name != "tracingBufferFull" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "tracingBufferFull" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "TracingBufferFullParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(39))
		if !ok || info.Name != "noRoamingNumberAvailable" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "noRoamingNumberAvailable" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "NoRoamingNbParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(27))
		if !ok || info.Name != "absentSubscriber" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "absentSubscriber" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "AbsentSubscriberParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(45))
		if !ok || info.Name != "busySubscriber" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "busySubscriber" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "BusySubscriberParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(46))
		if !ok || info.Name != "noSubscriberReply" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "noSubscriberReply" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "NoSubscriberReplyParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(13))
		if !ok || info.Name != "callBarred" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "callBarred" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "CallBarredParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(14))
		if !ok || info.Name != "forwardingViolation" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "forwardingViolation" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "ForwardingViolationParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(47))
		if !ok || info.Name != "forwardingFailed" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "forwardingFailed" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "ForwardingFailedParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(15))
		if !ok || info.Name != "cug-Reject" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "cug-Reject" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "CUG-RejectParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(48))
		if !ok || info.Name != "or-NotAllowed" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "or-NotAllowed" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "OR-NotAllowedParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(49))
		if !ok || info.Name != "ati-NotAllowed" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "ati-NotAllowed" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "ATI-NotAllowedParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(60))
		if !ok || info.Name != "atsi-NotAllowed" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "atsi-NotAllowed" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "ATSI-NotAllowedParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(61))
		if !ok || info.Name != "atm-NotAllowed" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "atm-NotAllowed" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "ATM-NotAllowedParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(62))
		if !ok || info.Name != "informationNotAvailable" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "informationNotAvailable" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "InformationNotAvailableParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(16))
		if !ok || info.Name != "illegalSS-Operation" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "illegalSS-Operation" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "IllegalSS-OperationParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(17))
		if !ok || info.Name != "ss-ErrorStatus" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "ss-ErrorStatus" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "SS-Status" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(18))
		if !ok || info.Name != "ss-NotAvailable" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "ss-NotAvailable" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "SS-NotAvailableParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(19))
		if !ok || info.Name != "ss-SubscriptionViolation" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "ss-SubscriptionViolation" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "SS-SubscriptionViolationParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(20))
		if !ok || info.Name != "ss-Incompatibility" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "ss-Incompatibility" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "SS-IncompatibilityCause" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(71))
		if !ok || info.Name != "unknownAlphabet" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "unknownAlphabet" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(72))
		if !ok || info.Name != "ussd-Busy" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "ussd-Busy" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(37))
		if !ok || info.Name != "pw-RegistrationFailure" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "pw-RegistrationFailure" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "PW-RegistrationFailureCause" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(38))
		if !ok || info.Name != "negativePW-Check" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "negativePW-Check" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(43))
		if !ok || info.Name != "numberOfPW-AttemptsViolation" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "numberOfPW-AttemptsViolation" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(29))
		if !ok || info.Name != "shortTermDenial" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "shortTermDenial" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "ShortTermDenialParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(30))
		if !ok || info.Name != "longTermDenial" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "longTermDenial" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "LongTermDenialParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(31))
		if !ok || info.Name != "subscriberBusyForMT-SMS" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "subscriberBusyForMT-SMS" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "SubBusyForMT-SMS-Param" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(32))
		if !ok || info.Name != "sm-DeliveryFailure" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "sm-DeliveryFailure" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "SM-DeliveryFailureCause" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(33))
		if !ok || info.Name != "messageWaitingListFull" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "messageWaitingListFull" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "MessageWaitListFullParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(6))
		if !ok || info.Name != "absentSubscriberSM" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "absentSubscriberSM" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "AbsentSubscriberSM-Param" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(50))
		if !ok || info.Name != "noGroupCallNumberAvailable" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "noGroupCallNumberAvailable" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "NoGroupCallNbParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(22))
		if !ok || info.Name != "ongoingGroupCall" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "ongoingGroupCall" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "OngoingGroupCallParam" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(52))
		if !ok || info.Name != "unauthorizedRequestingNetwork" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "unauthorizedRequestingNetwork" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "UnauthorizedRequestingNetwork-Param" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(53))
		if !ok || info.Name != "unauthorizedLCSClient" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "unauthorizedLCSClient" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "UnauthorizedLCSClient-Param" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(54))
		if !ok || info.Name != "positionMethodFailure" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "positionMethodFailure" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "PositionMethodFailure-Param" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(58))
		if !ok || info.Name != "unknownOrUnreachableLCSClient" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "unknownOrUnreachableLCSClient" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "UnknownOrUnreachableLCSClient-Param" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
	{
		info, ok := v21_map_errors.LookupHistoricalMAPError(v21_map_errors.HistoricalMAPErrorCode(59))
		if !ok || info.Name != "mm-EventNotSupported" || info.Source.Module != "MAP-Errors" || info.Source.Assignment != "mm-EventNotSupported" || info.Source.SHA256 != "0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054" || info.Source.Edition != "18.0.0" || info.Source.Document != "3GPP TS 29.002" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter == nil || info.Parameter.ASN1Name != "MM-EventNotSupported-Param" {
			t.Fatalf("parameter metadata %+v", info.Parameter)
		}
	}
}
