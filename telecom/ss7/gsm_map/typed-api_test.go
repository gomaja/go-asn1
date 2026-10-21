// Code generated from the MAP typed API regression contract. DO NOT EDIT.

package gsm_map_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	mapvalues "github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
	mapbindings "github.com/gomaja/go-asn1/telecom/ss7/gsm_map/bindings"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/runtime/ber"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_er_datatypes"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_errors"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map/v21_map_ss_datatypes"
)

func TestTypeRefModuleOIDMatchesPinnedSource(t *testing.T) {
	// MAP-SM-DataTypes module identifier, TS 29.002 V19.1.0 §17.6.
	const sourceModuleOID = "0.4.0.0.1.3.16.22"
	info := mapbindings.SendRoutingInfoForSMOperation().Info()
	if info.Argument == nil || info.Argument.ModuleOID != sourceModuleOID {
		t.Fatalf("argument module OID = %+v, want %s", info.Argument, sourceModuleOID)
	}
}

func TestInvalidCodecSentinelAcrossPackages(t *testing.T) {
	var root mapvalues.ValueCodec[int]
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
	var mapOperation mapbindings.Operation[mapvalues.SendRoutingInfoArg, mapvalues.SendRoutingInfoRes, mapvalues.SendRoutingInfoErrors]
	var ssOperation mapbindings.SSOperation[mapvalues.BERValue[mapvalues.SSUserData], mapvalues.BERValue[mapvalues.SSUserData], mapvalues.SSProcessUnstructuredSSDataErrors]
	for _, attempt := range []func() error{
		func() error { _, err := mapOperation.DecodeError(0, nil, false); return err },
		func() error { _, err := mapOperation.EncodeError(mapvalues.SendRoutingInfoErrors{}); return err },
		func() error { _, err := ssOperation.DecodeError(0, nil, false); return err },
		func() error {
			_, err := ssOperation.EncodeError(mapvalues.SSProcessUnstructuredSSDataErrors{})
			return err
		},
		func() error { _, err := mapbindings.SendRoutingInfoOperation().DecodeError(-1, nil, false); return err },
	} {
		if err := attempt(); !errors.Is(err, ber.ErrInvalidBinding) {
			t.Fatalf("descriptor returned %v", err)
		}
	}
}

func TestEveryTypedBindingCompiles(t *testing.T) {
	var _ mapbindings.Operation[mapvalues.SendRoutingInfoArg, mapvalues.SendRoutingInfoRes, mapvalues.SendRoutingInfoErrors] = mapbindings.SendRoutingInfoOperation()
	var _ mapbindings.Operation[mapvalues.ProvideRoamingNumberArg, mapvalues.ProvideRoamingNumberRes, mapvalues.ProvideRoamingNumberErrors] = mapbindings.ProvideRoamingNumberOperation()
	var _ mapbindings.Operation[mapvalues.ResumeCallHandlingArg, mapvalues.ResumeCallHandlingRes, mapvalues.ResumeCallHandlingErrors] = mapbindings.ResumeCallHandlingOperation()
	var _ mapbindings.Operation[mapvalues.SetReportingStateArg, mapvalues.SetReportingStateRes, mapvalues.SetReportingStateErrors] = mapbindings.SetReportingStateOperation()
	var _ mapbindings.Operation[mapvalues.StatusReportArg, mapvalues.StatusReportRes, mapvalues.StatusReportErrors] = mapbindings.StatusReportOperation()
	var _ mapbindings.Operation[mapvalues.RemoteUserFreeArg, mapvalues.RemoteUserFreeRes, mapvalues.RemoteUserFreeErrors] = mapbindings.RemoteUserFreeOperation()
	var _ mapbindings.Operation[mapvalues.ISTAlertArg, mapvalues.ISTAlertRes, mapvalues.IstAlertErrors] = mapbindings.IstAlertOperation()
	var _ mapbindings.Operation[mapvalues.ISTCommandArg, mapvalues.ISTCommandRes, mapvalues.IstCommandErrors] = mapbindings.IstCommandOperation()
	var _ mapbindings.Operation[mapvalues.ReleaseResourcesArg, mapvalues.ReleaseResourcesRes, mapvalues.ReleaseResourcesErrors] = mapbindings.ReleaseResourcesOperation()
	var _ mapbindings.Operation[mapvalues.PrepareGroupCallArg, mapvalues.PrepareGroupCallRes, mapvalues.PrepareGroupCallErrors] = mapbindings.PrepareGroupCallOperation()
	var _ mapbindings.Operation[mapvalues.SendGroupCallEndSignalArg, mapvalues.SendGroupCallEndSignalRes, mapvalues.SendGroupCallEndSignalErrors] = mapbindings.SendGroupCallEndSignalOperation()
	var _ mapbindings.Operation[mapvalues.ProcessGroupCallSignallingArg, mapvalues.NoParameter, mapvalues.ProcessGroupCallSignallingErrors] = mapbindings.ProcessGroupCallSignallingOperation()
	var _ mapbindings.Operation[mapvalues.ForwardGroupCallSignallingArg, mapvalues.NoParameter, mapvalues.ForwardGroupCallSignallingErrors] = mapbindings.ForwardGroupCallSignallingOperation()
	var _ mapbindings.Operation[mapvalues.SendGroupCallInfoArg, mapvalues.SendGroupCallInfoRes, mapvalues.SendGroupCallInfoErrors] = mapbindings.SendGroupCallInfoOperation()
	var _ mapbindings.Operation[mapvalues.RoutingInfoForLCSArg, mapvalues.RoutingInfoForLCSRes, mapvalues.SendRoutingInfoForLCSErrors] = mapbindings.SendRoutingInfoForLCSOperation()
	var _ mapbindings.Operation[mapvalues.ProvideSubscriberLocationArg, mapvalues.ProvideSubscriberLocationRes, mapvalues.ProvideSubscriberLocationErrors] = mapbindings.ProvideSubscriberLocationOperation()
	var _ mapbindings.Operation[mapvalues.SubscriberLocationReportArg, mapvalues.SubscriberLocationReportRes, mapvalues.SubscriberLocationReportErrors] = mapbindings.SubscriberLocationReportOperation()
	var _ mapbindings.Operation[mapvalues.UpdateLocationArg, mapvalues.UpdateLocationRes, mapvalues.UpdateLocationErrors] = mapbindings.UpdateLocationOperation()
	var _ mapbindings.Operation[mapvalues.CancelLocationArg, mapvalues.CancelLocationRes, mapvalues.CancelLocationErrors] = mapbindings.CancelLocationOperation()
	var _ mapbindings.Operation[mapvalues.PurgeMSArg, mapvalues.PurgeMSRes, mapvalues.PurgeMSErrors] = mapbindings.PurgeMSOperation()
	var _ mapbindings.Operation[mapvalues.SendIdentificationArg, mapvalues.SendIdentificationRes, mapvalues.SendIdentificationErrors] = mapbindings.SendIdentificationOperation()
	var _ mapbindings.Operation[mapvalues.UpdateGprsLocationArg, mapvalues.UpdateGprsLocationRes, mapvalues.UpdateGprsLocationErrors] = mapbindings.UpdateGprsLocationOperation()
	var _ mapbindings.Operation[mapvalues.ProvideSubscriberInfoArg, mapvalues.ProvideSubscriberInfoRes, mapvalues.ProvideSubscriberInfoErrors] = mapbindings.ProvideSubscriberInfoOperation()
	var _ mapbindings.Operation[mapvalues.AnyTimeInterrogationArg, mapvalues.AnyTimeInterrogationRes, mapvalues.AnyTimeInterrogationErrors] = mapbindings.AnyTimeInterrogationOperation()
	var _ mapbindings.Operation[mapvalues.AnyTimeSubscriptionInterrogationArg, mapvalues.AnyTimeSubscriptionInterrogationRes, mapvalues.AnyTimeSubscriptionInterrogationErrors] = mapbindings.AnyTimeSubscriptionInterrogationOperation()
	var _ mapbindings.Operation[mapvalues.AnyTimeModificationArg, mapvalues.AnyTimeModificationRes, mapvalues.AnyTimeModificationErrors] = mapbindings.AnyTimeModificationOperation()
	var _ mapbindings.Operation[mapvalues.NoteSubscriberDataModifiedArg, mapvalues.NoteSubscriberDataModifiedRes, mapvalues.NoteSubscriberDataModifiedErrors] = mapbindings.NoteSubscriberDataModifiedOperation()
	var _ mapbindings.Operation[mapvalues.PrepareHOArg, mapvalues.PrepareHORes, mapvalues.PrepareHandoverErrors] = mapbindings.PrepareHandoverOperation()
	var _ mapbindings.Operation[mapvalues.SendEndSignalArg, mapvalues.SendEndSignalRes, mapvalues.SendEndSignalErrors] = mapbindings.SendEndSignalOperation()
	var _ mapbindings.Operation[mapvalues.ProcessAccessSignallingArg, mapvalues.NoParameter, mapvalues.ProcessAccessSignallingErrors] = mapbindings.ProcessAccessSignallingOperation()
	var _ mapbindings.Operation[mapvalues.ForwardAccessSignallingArg, mapvalues.NoParameter, mapvalues.ForwardAccessSignallingErrors] = mapbindings.ForwardAccessSignallingOperation()
	var _ mapbindings.Operation[mapvalues.PrepareSubsequentHOArg, mapvalues.PrepareSubsequentHORes, mapvalues.PrepareSubsequentHandoverErrors] = mapbindings.PrepareSubsequentHandoverOperation()
	var _ mapbindings.Operation[mapvalues.SendAuthenticationInfoArg, mapvalues.SendAuthenticationInfoRes, mapvalues.SendAuthenticationInfoErrors] = mapbindings.SendAuthenticationInfoOperation()
	var _ mapbindings.Operation[mapvalues.AuthenticationFailureReportArg, mapvalues.AuthenticationFailureReportRes, mapvalues.AuthenticationFailureReportErrors] = mapbindings.AuthenticationFailureReportOperation()
	var _ mapbindings.Operation[mapvalues.CheckIMEIArg, mapvalues.CheckIMEIRes, mapvalues.CheckIMEIErrors] = mapbindings.CheckIMEIOperation()
	var _ mapbindings.Operation[mapvalues.InsertSubscriberDataArg, mapvalues.InsertSubscriberDataRes, mapvalues.InsertSubscriberDataErrors] = mapbindings.InsertSubscriberDataOperation()
	var _ mapbindings.Operation[mapvalues.DeleteSubscriberDataArg, mapvalues.DeleteSubscriberDataRes, mapvalues.DeleteSubscriberDataErrors] = mapbindings.DeleteSubscriberDataOperation()
	var _ mapbindings.Operation[mapvalues.ResetArg, mapvalues.NoParameter, mapvalues.ResetErrors] = mapbindings.ResetOperation()
	var _ mapbindings.Operation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.ForwardCheckSSIndicationErrors] = mapbindings.ForwardCheckSSIndicationOperation()
	var _ mapbindings.Operation[mapvalues.RestoreDataArg, mapvalues.RestoreDataRes, mapvalues.RestoreDataErrors] = mapbindings.RestoreDataOperation()
	var _ mapbindings.Operation[mapvalues.SendRoutingInfoForGprsArg, mapvalues.SendRoutingInfoForGprsRes, mapvalues.SendRoutingInfoForGprsErrors] = mapbindings.SendRoutingInfoForGprsOperation()
	var _ mapbindings.Operation[mapvalues.FailureReportArg, mapvalues.FailureReportRes, mapvalues.FailureReportErrors] = mapbindings.FailureReportOperation()
	var _ mapbindings.Operation[mapvalues.NoteMsPresentForGprsArg, mapvalues.NoteMsPresentForGprsRes, mapvalues.NoteMsPresentForGprsErrors] = mapbindings.NoteMsPresentForGprsOperation()
	var _ mapbindings.Operation[mapvalues.NoteMMEventArg, mapvalues.NoteMMEventRes, mapvalues.NoteMMEventErrors] = mapbindings.NoteMMEventOperation()
	var _ mapbindings.Operation[mapvalues.UpdateVcsgLocationArg, mapvalues.UpdateVcsgLocationRes, mapvalues.UpdateVcsgLocationErrors] = mapbindings.UpdateVcsgLocationOperation()
	var _ mapbindings.Operation[mapvalues.CancelVcsgLocationArg, mapvalues.CancelVcsgLocationRes, mapvalues.CancelVcsgLocationErrors] = mapbindings.CancelVcsgLocationOperation()
	var _ mapbindings.Operation[mapvalues.ActivateTraceModeArg, mapvalues.ActivateTraceModeRes, mapvalues.ActivateTraceModeErrors] = mapbindings.ActivateTraceModeOperation()
	var _ mapbindings.Operation[mapvalues.DeactivateTraceModeArg, mapvalues.DeactivateTraceModeRes, mapvalues.DeactivateTraceModeErrors] = mapbindings.DeactivateTraceModeOperation()
	var _ mapbindings.Operation[mapvalues.BERValue[mapvalues.ISDNAddressString], mapvalues.BERValue[mapvalues.IMSI], mapvalues.SendIMSIErrors] = mapbindings.SendIMSIOperation()
	var _ mapbindings.Operation[mapvalues.RoutingInfoForSMArg, mapvalues.RoutingInfoForSMRes, mapvalues.SendRoutingInfoForSMErrors] = mapbindings.SendRoutingInfoForSMOperation()
	var _ mapbindings.Operation[mapvalues.MOForwardSMArg, mapvalues.MOForwardSMRes, mapvalues.MoForwardSMErrors] = mapbindings.MoForwardSMOperation()
	var _ mapbindings.Operation[mapvalues.MTForwardSMArg, mapvalues.MTForwardSMRes, mapvalues.MtForwardSMErrors] = mapbindings.MtForwardSMOperation()
	var _ mapbindings.Operation[mapvalues.ReportSMDeliveryStatusArg, mapvalues.ReportSMDeliveryStatusRes, mapvalues.ReportSMDeliveryStatusErrors] = mapbindings.ReportSMDeliveryStatusOperation()
	var _ mapbindings.Operation[mapvalues.AlertServiceCentreArg, mapvalues.NoParameter, mapvalues.AlertServiceCentreErrors] = mapbindings.AlertServiceCentreOperation()
	var _ mapbindings.Operation[mapvalues.InformServiceCentreArg, mapvalues.NoParameter, mapvalues.InformServiceCentreErrors] = mapbindings.InformServiceCentreOperation()
	var _ mapbindings.Operation[mapvalues.ReadyForSMArg, mapvalues.ReadyForSMRes, mapvalues.ReadyForSMErrors] = mapbindings.ReadyForSMOperation()
	var _ mapbindings.Operation[mapvalues.MTForwardSMVGCSArg, mapvalues.MTForwardSMVGCSRes, mapvalues.MtForwardSMVGCSErrors] = mapbindings.MtForwardSMVGCSOperation()
	var _ mapbindings.Operation[mapvalues.RegisterSSArg, mapvalues.SSInfo, mapvalues.RegisterSSErrors] = mapbindings.RegisterSSOperation()
	var _ mapbindings.Operation[mapvalues.SSForBSCode, mapvalues.SSInfo, mapvalues.EraseSSErrors] = mapbindings.EraseSSOperation()
	var _ mapbindings.Operation[mapvalues.SSForBSCode, mapvalues.SSInfo, mapvalues.ActivateSSErrors] = mapbindings.ActivateSSOperation()
	var _ mapbindings.Operation[mapvalues.SSForBSCode, mapvalues.SSInfo, mapvalues.DeactivateSSErrors] = mapbindings.DeactivateSSOperation()
	var _ mapbindings.Operation[mapvalues.SSForBSCode, mapvalues.InterrogateSSRes, mapvalues.InterrogateSSErrors] = mapbindings.InterrogateSSOperation()
	var _ mapbindings.Operation[mapvalues.USSDArg, mapvalues.USSDRes, mapvalues.ProcessUnstructuredSSRequestErrors] = mapbindings.ProcessUnstructuredSSRequestOperation()
	var _ mapbindings.Operation[mapvalues.USSDArg, mapvalues.USSDRes, mapvalues.UnstructuredSSRequestErrors] = mapbindings.UnstructuredSSRequestOperation()
	var _ mapbindings.Operation[mapvalues.USSDArg, mapvalues.NoParameter, mapvalues.UnstructuredSSNotifyErrors] = mapbindings.UnstructuredSSNotifyOperation()
	var _ mapbindings.Operation[mapvalues.BERValue[mapvalues.SSCode], mapvalues.BERValue[mapvalues.Password], mapvalues.RegisterPasswordErrors] = mapbindings.RegisterPasswordOperation()
	var _ mapbindings.Operation[mapvalues.BERValue[mapvalues.GuidanceInfo], mapvalues.BERValue[mapvalues.Password], mapvalues.GetPasswordErrors] = mapbindings.GetPasswordOperation()
	var _ mapbindings.Operation[mapvalues.SSInvocationNotificationArg, mapvalues.SSInvocationNotificationRes, mapvalues.SsInvocationNotificationErrors] = mapbindings.SsInvocationNotificationOperation()
	var _ mapbindings.Operation[mapvalues.RegisterCCEntryArg, mapvalues.RegisterCCEntryRes, mapvalues.RegisterCCEntryErrors] = mapbindings.RegisterCCEntryOperation()
	var _ mapbindings.Operation[mapvalues.EraseCCEntryArg, mapvalues.EraseCCEntryRes, mapvalues.EraseCCEntryErrors] = mapbindings.EraseCCEntryOperation()
	var _ mapbindings.SSOperation[mapvalues.BERValue[mapvalues.SSUserData], mapvalues.BERValue[mapvalues.SSUserData], mapvalues.SSProcessUnstructuredSSDataErrors] = mapbindings.SSProcessUnstructuredSSDataOperation()
	var _ mapbindings.SSOperation[mapvalues.NotifySSArg, mapvalues.NoParameter, mapvalues.SSNotifySSErrors] = mapbindings.SSNotifySSOperation()
	var _ mapbindings.SSOperation[mapvalues.ForwardChargeAdviceArg, mapvalues.NoParameter, mapvalues.SSForwardChargeAdviceErrors] = mapbindings.SSForwardChargeAdviceOperation()
	var _ mapbindings.SSOperation[mapvalues.ForwardCUGInfoArg, mapvalues.NoParameter, mapvalues.SSForwardCUGInfoErrors] = mapbindings.SSForwardCUGInfoOperation()
	var _ mapbindings.SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSBuildMPTYErrors] = mapbindings.SSBuildMPTYOperation()
	var _ mapbindings.SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSHoldMPTYErrors] = mapbindings.SSHoldMPTYOperation()
	var _ mapbindings.SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSRetrieveMPTYErrors] = mapbindings.SSRetrieveMPTYOperation()
	var _ mapbindings.SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSSplitMPTYErrors] = mapbindings.SSSplitMPTYOperation()
	var _ mapbindings.SSOperation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSExplicitCTErrors] = mapbindings.SSExplicitCTOperation()
	var _ mapbindings.SSOperation[mapvalues.AccessRegisterCCEntryArg, v21_map_ss_datatypes.SSRegisterCCEntryRes, mapvalues.SSAccessRegisterCCEntryErrors] = mapbindings.SSAccessRegisterCCEntryOperation()
	var _ mapbindings.SSOperation[mapvalues.CallDeflectionArg, mapvalues.NoParameter, mapvalues.SSCallDeflectionErrors] = mapbindings.SSCallDeflectionOperation()
	var _ mapbindings.SSOperation[mapvalues.UserUserServiceArg, mapvalues.NoParameter, mapvalues.SSUserUserServiceErrors] = mapbindings.SSUserUserServiceOperation()
	var _ mapbindings.SSOperation[mapvalues.LocationNotificationArg, mapvalues.LocationNotificationRes, mapvalues.SSLcsLocationNotificationErrors] = mapbindings.SSLcsLocationNotificationOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSMOLRArg, mapvalues.LCSMOLRRes, mapvalues.SSLcsMOLRErrors] = mapbindings.SSLcsMOLROperation()
	var _ mapbindings.SSOperation[mapvalues.LCSAreaEventRequestArg, mapvalues.NoParameter, mapvalues.SSLcsAreaEventRequestErrors] = mapbindings.SSLcsAreaEventRequestOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSAreaEventReportArg, mapvalues.NoParameter, mapvalues.SSLcsAreaEventReportErrors] = mapbindings.SSLcsAreaEventReportOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSAreaEventCancellationArg, mapvalues.NoParameter, mapvalues.SSLcsAreaEventCancellationErrors] = mapbindings.SSLcsAreaEventCancellationOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSPeriodicLocationRequestArg, mapvalues.LCSPeriodicLocationRequestRes, mapvalues.SSLcsPeriodicLocationRequestErrors] = mapbindings.SSLcsPeriodicLocationRequestOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSLocationUpdateArg, mapvalues.LCSLocationUpdateRes, mapvalues.SSLcsLocationUpdateErrors] = mapbindings.SSLcsLocationUpdateOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSPeriodicLocationCancellationArg, mapvalues.NoParameter, mapvalues.SSLcsPeriodicLocationCancellationErrors] = mapbindings.SSLcsPeriodicLocationCancellationOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSPeriodicTriggeredInvokeArg, mapvalues.LCSPeriodicTriggeredInvokeRes, mapvalues.SSLcsPeriodicTriggeredInvokeErrors] = mapbindings.SSLcsPeriodicTriggeredInvokeOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSEventReportArg, mapvalues.LCSEventReportRes, mapvalues.SSLcsEventReportErrors] = mapbindings.SSLcsEventReportOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSCancelDeferredLocationArg, mapvalues.NoParameter, mapvalues.SSLcsCancelDeferredLocationErrors] = mapbindings.SSLcsCancelDeferredLocationOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSCancelDeferredLocationArg, mapvalues.NoParameter, mapvalues.SSLcsMSCancelDeferredLocationErrors] = mapbindings.SSLcsMSCancelDeferredLocationOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSLocationPrivacySettingArg, mapvalues.NoParameter, mapvalues.SSLcsLocationPrivacySettingErrors] = mapbindings.SSLcsLocationPrivacySettingOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSPruAssociationArg, mapvalues.LCSPruAssociationRes, mapvalues.SSLcsPruAssociationErrors] = mapbindings.SSLcsPruAssociationOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSPruDisassociationArg, mapvalues.NoParameter, mapvalues.SSLcsPruDisassociationErrors] = mapbindings.SSLcsPruDisassociationOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSSLMOLRArg, mapvalues.LCSSLMOLRRes, mapvalues.SSLcsSLMOLRErrors] = mapbindings.SSLcsSLMOLROperation()
	var _ mapbindings.SSOperation[mapvalues.LCSSLMTLRArg, mapvalues.LCSSLMTLRRes, mapvalues.SSLcsSLMTLRErrors] = mapbindings.SSLcsSLMTLROperation()
	var _ mapbindings.SSOperation[mapvalues.LCSDLRSPPTransportArg, mapvalues.LCSDLRSPPTransportRes, mapvalues.SSLcsDLRSPPTransportErrors] = mapbindings.SSLcsDLRSPPTransportOperation()
	var _ mapbindings.SSOperation[mapvalues.LCSULRSPPTransportArg, mapvalues.LCSULRSPPTransportRes, mapvalues.SSLcsULRSPPTransportErrors] = mapbindings.SSLcsULRSPPTransportOperation()
	var _ mapbindings.ErrorDescriptor[mapvalues.SystemFailureParam] = mapbindings.SystemFailureErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.DataMissingParam] = mapbindings.DataMissingErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.UnexpectedDataParam] = mapbindings.UnexpectedDataValueErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.FacilityNotSupParam] = mapbindings.FacilityNotSupportedErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.IncompatibleTerminalParam] = mapbindings.IncompatibleTerminalErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.ResourceLimitationParam] = mapbindings.ResourceLimitationErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.UnknownSubscriberParam] = mapbindings.UnknownSubscriberErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NumberChangedParam] = mapbindings.NumberChangedErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NoParameter] = mapbindings.UnknownMSCErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.UnidentifiedSubParam] = mapbindings.UnidentifiedSubscriberErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NoParameter] = mapbindings.UnknownEquipmentErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.RoamingNotAllowedParam] = mapbindings.RoamingNotAllowedErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.IllegalSubscriberParam] = mapbindings.IllegalSubscriberErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.IllegalEquipmentParam] = mapbindings.IllegalEquipmentErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.BearerServNotProvParam] = mapbindings.BearerServiceNotProvisionedErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.TeleservNotProvParam] = mapbindings.TeleserviceNotProvisionedErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NoParameter] = mapbindings.NoHandoverNumberAvailableErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NoParameter] = mapbindings.SubsequentHandoverFailureErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.TargetCellOutsideGCAParam] = mapbindings.TargetCellOutsideGroupCallAreaErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.TracingBufferFullParam] = mapbindings.TracingBufferFullErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NoRoamingNbParam] = mapbindings.NoRoamingNumberAvailableErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.AbsentSubscriberParam] = mapbindings.AbsentSubscriberErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.BusySubscriberParam] = mapbindings.BusySubscriberErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NoSubscriberReplyParam] = mapbindings.NoSubscriberReplyErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.CallBarredParam] = mapbindings.CallBarredErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.ForwardingViolationParam] = mapbindings.ForwardingViolationErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.ForwardingFailedParam] = mapbindings.ForwardingFailedErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.CUGRejectParam] = mapbindings.CugRejectErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.ORNotAllowedParam] = mapbindings.OrNotAllowedErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.ATINotAllowedParam] = mapbindings.AtiNotAllowedErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.ATSINotAllowedParam] = mapbindings.AtsiNotAllowedErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.ATMNotAllowedParam] = mapbindings.AtmNotAllowedErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.InformationNotAvailableParam] = mapbindings.InformationNotAvailableErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.IllegalSSOperationParam] = mapbindings.IllegalSSOperationErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.BERValue[mapvalues.SSStatus]] = mapbindings.SsErrorStatusErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.SSNotAvailableParam] = mapbindings.SsNotAvailableErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.SSSubscriptionViolationParam] = mapbindings.SsSubscriptionViolationErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.SSIncompatibilityCause] = mapbindings.SsIncompatibilityErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NoParameter] = mapbindings.UnknownAlphabetErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NoParameter] = mapbindings.UssdBusyErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.BERValue[mapvalues.PWRegistrationFailureCause]] = mapbindings.PwRegistrationFailureErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NoParameter] = mapbindings.NegativePWCheckErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NoParameter] = mapbindings.NumberOfPWAttemptsViolationErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.ShortTermDenialParam] = mapbindings.ShortTermDenialErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.LongTermDenialParam] = mapbindings.LongTermDenialErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.SubBusyForMTSMSParam] = mapbindings.SubscriberBusyForMTSMSErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.SMDeliveryFailureCause] = mapbindings.SmDeliveryFailureErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.MessageWaitListFullParam] = mapbindings.MessageWaitingListFullErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.AbsentSubscriberSMParam] = mapbindings.AbsentSubscriberSMErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.NoGroupCallNbParam] = mapbindings.NoGroupCallNumberAvailableErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.OngoingGroupCallParam] = mapbindings.OngoingGroupCallErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.UnauthorizedRequestingNetworkParam] = mapbindings.UnauthorizedRequestingNetworkErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.UnauthorizedLCSClientParam] = mapbindings.UnauthorizedLCSClientErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.PositionMethodFailureParam] = mapbindings.PositionMethodFailureErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.UnknownOrUnreachableLCSClientParam] = mapbindings.UnknownOrUnreachableLCSClientErrorDescriptor()
	var _ mapbindings.ErrorDescriptor[mapvalues.MMEventNotSupportedParam] = mapbindings.MmEventNotSupportedErrorDescriptor()
	var _ mapbindings.SSErrorDescriptor[mapvalues.NoParameter] = mapbindings.SSResourcesNotAvailableErrorDescriptor()
	var _ mapbindings.SSErrorDescriptor[mapvalues.NoParameter] = mapbindings.SSMaxNumberOfMPTYParticipantsExceededErrorDescriptor()
	var _ mapbindings.SSErrorDescriptor[mapvalues.NoParameter] = mapbindings.SSInvalidDeflectedToNumberErrorDescriptor()
	var _ mapbindings.SSErrorDescriptor[mapvalues.NoParameter] = mapbindings.SSSpecialServiceCodeErrorDescriptor()
	var _ mapbindings.SSErrorDescriptor[mapvalues.NoParameter] = mapbindings.SSDeflectionToServedSubscriberErrorDescriptor()
	var _ mapbindings.SSErrorDescriptor[mapvalues.NoParameter] = mapbindings.SSRejectedByNetworkErrorDescriptor()
	var _ mapbindings.SSErrorDescriptor[mapvalues.NoParameter] = mapbindings.SSRejectedByUserErrorDescriptor()
	var _ mapbindings.SSErrorDescriptor[mapvalues.NoParameter] = mapbindings.SSLcsInvalidPruErrorDescriptor()
	var _ mapbindings.SSErrorDescriptor[mapvalues.PruAssociationRejParam] = mapbindings.SSLcsPruAssociationRejErrorDescriptor()
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
func checkBindingType(t *testing.T, got *mapvalues.TypeRef, name string) {
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
func checkBindingSource(t *testing.T, source mapvalues.SourceRef, row bindingRow) {
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
	if len(mapvalues.Operations()) != 70 || len(mapvalues.Errors()) != 56 {
		t.Fatal("catalogue cardinality")
	}
	for _, row := range rows {
		info, ok := mapvalues.LookupOperation(mapvalues.MAPOperationCode(row.Code))
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
		if len(row.Linked) == 1 && info.Linked[0] != mapvalues.GetPassword {
			t.Fatal(info.Linked)
		}
	}
	for _, row := range bindingRows(t, `[{"name":"systemFailure","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SystemFailureParam","errors":[],"linked":[],"code":34},{"name":"dataMissing","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"DataMissingParam","errors":[],"linked":[],"code":35},{"name":"unexpectedDataValue","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnexpectedDataParam","errors":[],"linked":[],"code":36},{"name":"facilityNotSupported","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"FacilityNotSupParam","errors":[],"linked":[],"code":21},{"name":"incompatibleTerminal","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"IncompatibleTerminalParam","errors":[],"linked":[],"code":28},{"name":"resourceLimitation","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ResourceLimitationParam","errors":[],"linked":[],"code":51},{"name":"unknownSubscriber","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnknownSubscriberParam","errors":[],"linked":[],"code":1},{"name":"numberChanged","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"NumberChangedParam","errors":[],"linked":[],"code":44},{"name":"unknownMSC","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":3},{"name":"unidentifiedSubscriber","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnidentifiedSubParam","errors":[],"linked":[],"code":5},{"name":"unknownEquipment","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":7},{"name":"roamingNotAllowed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"RoamingNotAllowedParam","errors":[],"linked":[],"code":8},{"name":"illegalSubscriber","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"IllegalSubscriberParam","errors":[],"linked":[],"code":9},{"name":"illegalEquipment","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"IllegalEquipmentParam","errors":[],"linked":[],"code":12},{"name":"bearerServiceNotProvisioned","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"BearerServNotProvParam","errors":[],"linked":[],"code":10},{"name":"teleserviceNotProvisioned","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"TeleservNotProvParam","errors":[],"linked":[],"code":11},{"name":"noHandoverNumberAvailable","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":25},{"name":"subsequentHandoverFailure","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":26},{"name":"targetCellOutsideGroupCallArea","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"TargetCellOutsideGCA-Param","errors":[],"linked":[],"code":42},{"name":"tracingBufferFull","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"TracingBufferFullParam","errors":[],"linked":[],"code":40},{"name":"noRoamingNumberAvailable","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"NoRoamingNbParam","errors":[],"linked":[],"code":39},{"name":"absentSubscriber","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"AbsentSubscriberParam","errors":[],"linked":[],"code":27},{"name":"busySubscriber","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"BusySubscriberParam","errors":[],"linked":[],"code":45},{"name":"noSubscriberReply","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"NoSubscriberReplyParam","errors":[],"linked":[],"code":46},{"name":"callBarred","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"CallBarredParam","errors":[],"linked":[],"code":13},{"name":"forwardingViolation","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ForwardingViolationParam","errors":[],"linked":[],"code":14},{"name":"forwardingFailed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ForwardingFailedParam","errors":[],"linked":[],"code":47},{"name":"cug-Reject","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"CUG-RejectParam","errors":[],"linked":[],"code":15},{"name":"or-NotAllowed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"OR-NotAllowedParam","errors":[],"linked":[],"code":48},{"name":"ati-NotAllowed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ATI-NotAllowedParam","errors":[],"linked":[],"code":49},{"name":"atsi-NotAllowed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ATSI-NotAllowedParam","errors":[],"linked":[],"code":60},{"name":"atm-NotAllowed","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ATM-NotAllowedParam","errors":[],"linked":[],"code":61},{"name":"informationNotAvailable","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"InformationNotAvailableParam","errors":[],"linked":[],"code":62},{"name":"illegalSS-Operation","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"IllegalSS-OperationParam","errors":[],"linked":[],"code":16},{"name":"ss-ErrorStatus","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SS-Status","errors":[],"linked":[],"code":17},{"name":"ss-NotAvailable","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SS-NotAvailableParam","errors":[],"linked":[],"code":18},{"name":"ss-SubscriptionViolation","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SS-SubscriptionViolationParam","errors":[],"linked":[],"code":19},{"name":"ss-Incompatibility","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SS-IncompatibilityCause","errors":[],"linked":[],"code":20},{"name":"unknownAlphabet","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":71},{"name":"ussd-Busy","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":72},{"name":"pw-RegistrationFailure","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"PW-RegistrationFailureCause","errors":[],"linked":[],"code":37},{"name":"negativePW-Check","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":38},{"name":"numberOfPW-AttemptsViolation","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","errors":[],"linked":[],"code":43},{"name":"shortTermDenial","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"ShortTermDenialParam","errors":[],"linked":[],"code":29},{"name":"longTermDenial","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"LongTermDenialParam","errors":[],"linked":[],"code":30},{"name":"subscriberBusyForMT-SMS","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SubBusyForMT-SMS-Param","errors":[],"linked":[],"code":31},{"name":"sm-DeliveryFailure","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"SM-DeliveryFailureCause","errors":[],"linked":[],"code":32},{"name":"messageWaitingListFull","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"MessageWaitListFullParam","errors":[],"linked":[],"code":33},{"name":"absentSubscriberSM","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"AbsentSubscriberSM-Param","errors":[],"linked":[],"code":6},{"name":"noGroupCallNumberAvailable","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"NoGroupCallNbParam","errors":[],"linked":[],"code":50},{"name":"ongoingGroupCall","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"OngoingGroupCallParam","errors":[],"linked":[],"code":22},{"name":"unauthorizedRequestingNetwork","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnauthorizedRequestingNetwork-Param","errors":[],"linked":[],"code":52},{"name":"unauthorizedLCSClient","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnauthorizedLCSClient-Param","errors":[],"linked":[],"code":53},{"name":"positionMethodFailure","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"PositionMethodFailure-Param","errors":[],"linked":[],"code":54},{"name":"unknownOrUnreachableLCSClient","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"UnknownOrUnreachableLCSClient-Param","errors":[],"linked":[],"code":58},{"name":"mm-EventNotSupported","module":"MAP-Errors","sha256":"fbe39b6070e3fb7e2a3a6f55b319b24491a8b413321507ddd7145b1a7b4a3346","parameter":"MM-EventNotSupported-Param","errors":[],"linked":[],"code":59}]`) {
		info, ok := mapvalues.LookupError(mapvalues.MAPErrorCode(row.Code))
		if !ok || info.Name != row.Name {
			t.Fatalf("missing error %+v", row)
		}
		checkBindingSource(t, info.Source, row)
		checkBindingType(t, info.Parameter, row.Parameter)
		if info.ParameterOptional != nil {
			t.Fatal("comment-derived optionality")
		}
	}
	if _, ok := mapvalues.LookupOperation(-1); ok {
		t.Fatal("unknown operation")
	}
	if _, ok := mapvalues.LookupError(-1); ok {
		t.Fatal("unknown error")
	}
}
func TestCompleteSSDescriptorCatalogue(t *testing.T) {
	if len(mapvalues.SSOperations()) != 31 || len(mapvalues.SSErrors()) != 9 {
		t.Fatal("SS cardinality")
	}
	for _, row := range bindingRows(t, `[{"name":"processUnstructuredSS-Data","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"SS-UserData","result":"SS-UserData","code":19,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"notifySS","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"NotifySS-Arg","code":16,"errors":[],"linked":[],"error_bindings":[]},{"name":"forwardChargeAdvice","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"ForwardChargeAdviceArg","code":125,"errors":[],"linked":[],"error_bindings":[]},{"name":"forwardCUG-Info","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"ForwardCUG-InfoArg","code":120,"errors":[],"linked":[],"error_bindings":[]},{"name":"buildMPTY","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","code":124,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-NotAvailable","ss-Incompatibility","systemFailure","resourcesNotAvailable","maxNumberOfMPTY-ParticipantsExceeded"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-NotAvailable","kind":"ERROR","module":"MAP-Errors","line":384,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-NotAvailableParam","code":18,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsNotAvailable","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSNotAvailableParam"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"resourcesNotAvailable","kind":"ERROR","module":"SS-Errors","line":26,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":127,"errors":[],"linked":[],"constant":"SSResourcesNotAvailable","code_type":"SSErrorCode"},{"name":"maxNumberOfMPTY-ParticipantsExceeded","kind":"ERROR","module":"SS-Errors","line":28,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":126,"errors":[],"linked":[],"constant":"SSMaxNumberOfMPTYParticipantsExceeded","code_type":"SSErrorCode"}]},{"name":"holdMPTY","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","code":123,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-Incompatibility","facilityNotSupported","systemFailure"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"}]},{"name":"retrieveMPTY","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","code":122,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-Incompatibility","facilityNotSupported","systemFailure"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"}]},{"name":"splitMPTY","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","code":121,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-Incompatibility","facilityNotSupported","systemFailure"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"}]},{"name":"explicitCT","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","code":126,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-NotAvailable","ss-Incompatibility","facilityNotSupported","systemFailure","resourcesNotAvailable","callBarred"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-NotAvailable","kind":"ERROR","module":"MAP-Errors","line":384,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-NotAvailableParam","code":18,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsNotAvailable","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSNotAvailableParam"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"resourcesNotAvailable","kind":"ERROR","module":"SS-Errors","line":26,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":127,"errors":[],"linked":[],"constant":"SSResourcesNotAvailable","code_type":"SSErrorCode"},{"name":"callBarred","kind":"ERROR","module":"MAP-Errors","line":313,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"CallBarredParam","code":13,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsCallBarred","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERCallBarredParam"}]},{"name":"accessRegisterCCEntry","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"AccessRegisterCCEntryArg","result":"RegisterCC-EntryRes","code":119,"errors":["systemFailure","dataMissing","unexpectedDataValue","callBarred","illegalSS-Operation","ss-ErrorStatus","ss-Incompatibility","shortTermDenial","longTermDenial","facilityNotSupported"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"callBarred","kind":"ERROR","module":"MAP-Errors","line":313,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"CallBarredParam","code":13,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsCallBarred","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERCallBarredParam"},{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"shortTermDenial","kind":"ERROR","module":"MAP-Errors","line":421,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"ShortTermDenialParam","code":29,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsShortTermDenial","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERShortTermDenialParam"},{"name":"longTermDenial","kind":"ERROR","module":"MAP-Errors","line":427,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"LongTermDenialParam","code":30,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsLongTermDenial","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERLongTermDenialParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"}]},{"name":"callDeflection","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"CallDeflectionArg","code":117,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-NotAvailable","ss-Incompatibility","facilityNotSupported","systemFailure","resourcesNotAvailable","forwardingViolation","callBarred","deflectionToServedSubscriber","invalidDeflectedToNumber","specialServiceCode","forwardingFailed"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-NotAvailable","kind":"ERROR","module":"MAP-Errors","line":384,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-NotAvailableParam","code":18,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsNotAvailable","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSNotAvailableParam"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"resourcesNotAvailable","kind":"ERROR","module":"SS-Errors","line":26,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":127,"errors":[],"linked":[],"constant":"SSResourcesNotAvailable","code_type":"SSErrorCode"},{"name":"forwardingViolation","kind":"ERROR","module":"MAP-Errors","line":319,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"ForwardingViolationParam","code":14,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsForwardingViolation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERForwardingViolationParam"},{"name":"callBarred","kind":"ERROR","module":"MAP-Errors","line":313,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"CallBarredParam","code":13,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsCallBarred","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERCallBarredParam"},{"name":"deflectionToServedSubscriber","kind":"ERROR","module":"SS-Errors","line":34,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":123,"errors":[],"linked":[],"constant":"SSDeflectionToServedSubscriber","code_type":"SSErrorCode"},{"name":"invalidDeflectedToNumber","kind":"ERROR","module":"SS-Errors","line":30,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":125,"errors":[],"linked":[],"constant":"SSInvalidDeflectedToNumber","code_type":"SSErrorCode"},{"name":"specialServiceCode","kind":"ERROR","module":"SS-Errors","line":32,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":124,"errors":[],"linked":[],"constant":"SSSpecialServiceCode","code_type":"SSErrorCode"},{"name":"forwardingFailed","kind":"ERROR","module":"MAP-Errors","line":325,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"ForwardingFailedParam","code":47,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsForwardingFailed","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERForwardingFailedParam"}]},{"name":"userUserService","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"UserUserServiceArg","code":118,"errors":["illegalSS-Operation","ss-ErrorStatus","ss-NotAvailable","ss-Incompatibility","facilityNotSupported","systemFailure","resourcesNotAvailable","rejectedByNetwork","rejectedByUser"],"linked":[],"error_bindings":[{"name":"illegalSS-Operation","kind":"ERROR","module":"MAP-Errors","line":371,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"IllegalSS-OperationParam","code":16,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsIllegalSSOperation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERIllegalSSOperationParam"},{"name":"ss-ErrorStatus","kind":"ERROR","module":"MAP-Errors","line":378,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-Status","code":17,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsErrorStatus","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_ss_datatypes.BERValue[v21_map_ss_datatypes.SSSSStatus]"},{"name":"ss-NotAvailable","kind":"ERROR","module":"MAP-Errors","line":384,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-NotAvailableParam","code":18,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsNotAvailable","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSNotAvailableParam"},{"name":"ss-Incompatibility","kind":"ERROR","module":"MAP-Errors","line":398,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-IncompatibilityCause","code":20,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsIncompatibility","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSIncompatibilityCause"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"resourcesNotAvailable","kind":"ERROR","module":"SS-Errors","line":26,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":127,"errors":[],"linked":[],"constant":"SSResourcesNotAvailable","code_type":"SSErrorCode"},{"name":"rejectedByNetwork","kind":"ERROR","module":"SS-Errors","line":36,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":122,"errors":[],"linked":[],"constant":"SSRejectedByNetwork","code_type":"SSErrorCode"},{"name":"rejectedByUser","kind":"ERROR","module":"SS-Errors","line":38,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":121,"errors":[],"linked":[],"constant":"SSRejectedByUser","code_type":"SSErrorCode"}]},{"name":"lcs-LocationNotification","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LocationNotificationArg","result":"LocationNotificationRes","code":116,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-MOLR","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-MOLRArg","result":"LCS-MOLRRes","code":115,"errors":["systemFailure","unexpectedDataValue","dataMissing","facilityNotSupported","ss-SubscriptionViolation","positionMethodFailure"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"ss-SubscriptionViolation","kind":"ERROR","module":"MAP-Errors","line":391,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-SubscriptionViolationParam","code":19,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsSubscriptionViolation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSSubscriptionViolationParam"},{"name":"positionMethodFailure","kind":"ERROR","module":"MAP-Errors","line":486,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"PositionMethodFailure-Param","code":54,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsPositionMethodFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERPositionMethodFailureParam"}]},{"name":"lcs-AreaEventRequest","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-AreaEventRequestArg","code":114,"errors":["systemFailure","facilityNotSupported","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-AreaEventReport","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-AreaEventReportArg","code":113,"errors":["systemFailure","unexpectedDataValue","facilityNotSupported"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"}]},{"name":"lcs-AreaEventCancellation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-AreaEventCancellationArg","code":112,"errors":["systemFailure","facilityNotSupported","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-PeriodicLocationRequest","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-PeriodicLocationRequestArg","result":"LCS-PeriodicLocationRequestRes","code":111,"errors":["systemFailure","facilityNotSupported","unexpectedDataValue","dataMissing"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"}]},{"name":"lcs-LocationUpdate","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-LocationUpdateArg","result":"LCS-LocationUpdateRes","code":110,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-PeriodicLocationCancellation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-PeriodicLocationCancellationArg","code":109,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-PeriodicTriggeredInvoke","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-PeriodicTriggeredInvokeArg","result":"LCS-PeriodicTriggeredInvokeRes","code":108,"errors":["systemFailure","facilityNotSupported","unexpectedDataValue","dataMissing","resourceLimitation"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"resourceLimitation","kind":"ERROR","module":"MAP-Errors","line":195,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"ResourceLimitationParam","code":51,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsResourceLimitation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERResourceLimitationParam"}]},{"name":"lcs-EventReport","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-EventReportArg","result":"LCS-EventReportRes","code":107,"errors":["systemFailure","facilityNotSupported","ss-SubscriptionViolation","unexpectedDataValue","dataMissing","resourceLimitation"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"ss-SubscriptionViolation","kind":"ERROR","module":"MAP-Errors","line":391,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-SubscriptionViolationParam","code":19,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsSubscriptionViolation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSSubscriptionViolationParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"resourceLimitation","kind":"ERROR","module":"MAP-Errors","line":195,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"ResourceLimitationParam","code":51,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsResourceLimitation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERResourceLimitationParam"}]},{"name":"lcs-CancelDeferredLocation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-CancelDeferredLocationArg","code":106,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-MSCancelDeferredLocation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-CancelDeferredLocationArg","code":105,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-LocationPrivacySetting","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-LocationPrivacySettingArg","code":104,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-PruAssociation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-PruAssociationArg","result":"LCS-PruAssociationRes","code":103,"errors":["lcs-invalidPru","lcs-PruAssociationRej","systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"lcs-invalidPru","kind":"ERROR","module":"SS-Errors","line":40,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","code":120,"errors":[],"linked":[],"constant":"SSLcsInvalidPru","code_type":"SSErrorCode"},{"name":"lcs-PruAssociationRej","kind":"ERROR","module":"SS-Errors","line":42,"sha256":"b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e","parameter":"PruAssociationRejParam","code":119,"errors":[],"linked":[],"constant":"SSLcsPruAssociationRej","code_type":"SSErrorCode","parameter_binding":"PruAssociationRejParam"},{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-PruDisassociation","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-PruDisassociationArg","code":102,"errors":["systemFailure","unexpectedDataValue"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"}]},{"name":"lcs-SLMOLR","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-SLMOLRArg","result":"LCS-SLMOLRRes","code":101,"errors":["systemFailure","unexpectedDataValue","dataMissing","facilityNotSupported","ss-SubscriptionViolation","positionMethodFailure"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"},{"name":"ss-SubscriptionViolation","kind":"ERROR","module":"MAP-Errors","line":391,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SS-SubscriptionViolationParam","code":19,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSsSubscriptionViolation","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSSSubscriptionViolationParam"},{"name":"positionMethodFailure","kind":"ERROR","module":"MAP-Errors","line":486,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"PositionMethodFailure-Param","code":54,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsPositionMethodFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERPositionMethodFailureParam"}]},{"name":"lcs-SLMTLR","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-SLMTLRArg","result":"LCS-SLMTLRRes","code":100,"errors":["systemFailure","unexpectedDataValue","dataMissing","facilityNotSupported"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"unexpectedDataValue","kind":"ERROR","module":"MAP-Errors","line":175,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"UnexpectedDataParam","code":36,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsUnexpectedDataValue","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERUnexpectedDataParam"},{"name":"dataMissing","kind":"ERROR","module":"MAP-Errors","line":168,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"DataMissingParam","code":35,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsDataMissing","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERDataMissingParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"}]},{"name":"lcs-DLRSPPTransport","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-DLRSPPTransportArg","result":"LCS-DLRSPPTransportRes","code":99,"errors":["systemFailure","facilityNotSupported"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"}]},{"name":"lcs-ULRSPPTransport","module":"SS-Operations","sha256":"d3eba960d95875df7ffb757f3e944ee68d3172f407fb27cdeebec4e6e1317673","argument":"LCS-ULRSPPTransportArg","result":"LCS-ULRSPPTransportRes","code":98,"errors":["systemFailure","facilityNotSupported"],"linked":[],"error_bindings":[{"name":"systemFailure","kind":"ERROR","module":"MAP-Errors","line":162,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"SystemFailureParam","code":34,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsSystemFailure","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERSystemFailureParam"},{"name":"facilityNotSupported","kind":"ERROR","module":"MAP-Errors","line":182,"sha256":"0d1e884296d5c4ec0449110ca328008f7c263b331c78e4f5118b97945fe3a054","parameter":"FacilityNotSupParam","code":21,"errors":[],"linked":[],"constant":"v21_map_errors.HistoricalMAPErrorsFacilityNotSupported","code_type":"v21_map_errors.HistoricalMAPErrorCode","parameter_binding":"v21_map_er_datatypes.ERFacilityNotSupParam"}]}]`) {
		info, ok := mapvalues.LookupSSOperation(mapvalues.SSOperationCode(row.Code))
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
	contexts := mapvalues.ApplicationContexts()
	if len(contexts) != 44 {
		t.Fatal(len(contexts))
	}
	{
		oid := mapvalues.NetworkLocUpContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "networkLocUpContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.LocationCancellationContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "locationCancellationContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.RoamingNumberEnquiryContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "roamingNumberEnquiryContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.AuthenticationFailureReportContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "authenticationFailureReportContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.LocationInfoRetrievalContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "locationInfoRetrievalContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.ResetContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "resetContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.HandoverControlContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "handoverControlContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.EquipmentMngtContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "equipmentMngtContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.InfoRetrievalContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "infoRetrievalContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.InterVlrInfoRetrievalContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "interVlrInfoRetrievalContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.SubscriberDataMngtContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "subscriberDataMngtContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.TracingContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "tracingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.NetworkFunctionalSsContextV2()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 2 || c.Name != "networkFunctionalSsContext-v2" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.NetworkUnstructuredSsContextV2()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 2 || c.Name != "networkUnstructuredSsContext-v2" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.ShortMsgGatewayContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "shortMsgGatewayContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.ShortMsgMORelayContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "shortMsgMO-RelayContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.ShortMsgAlertContextV2()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 2 || c.Name != "shortMsgAlertContext-v2" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.MwdMngtContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "mwdMngtContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.ShortMsgMTRelayContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "shortMsgMT-RelayContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.ShortMsgMTRelayVGCSContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "shortMsgMT-Relay-VGCS-Context-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.ImsiRetrievalContextV2()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 2 || c.Name != "imsiRetrievalContext-v2" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.MsPurgingContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "msPurgingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.SubscriberInfoEnquiryContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "subscriberInfoEnquiryContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.AnyTimeInfoEnquiryContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "anyTimeInfoEnquiryContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.CallControlTransferContextV4()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 4 || c.Name != "callControlTransferContext-v4" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.SsInvocationNotificationContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "ss-InvocationNotificationContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.GroupCallControlContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "groupCallControlContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.GroupCallInfoRetrievalContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "groupCallInfoRetrievalContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.GprsLocationUpdateContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "gprsLocationUpdateContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.GprsLocationInfoRetrievalContextV4()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 4 || c.Name != "gprsLocationInfoRetrievalContext-v4" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.FailureReportContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "failureReportContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.GprsNotifyContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "gprsNotifyContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.ReportingContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "reportingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.CallCompletionContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "callCompletionContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.IstAlertingContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "istAlertingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.ServiceTerminationContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "serviceTerminationContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.LocationSvcGatewayContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "locationSvcGatewayContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.LocationSvcEnquiryContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "locationSvcEnquiryContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.MmEventReportingContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "mm-EventReportingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.AnyTimeInfoHandlingContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "anyTimeInfoHandlingContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.SubscriberDataModificationNotificationContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "subscriberDataModificationNotificationContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.ResourceManagementContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "resourceManagementContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.VcsgLocationUpdateContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "vcsgLocationUpdateContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	{
		oid := mapvalues.VcsgLocationCancellationContextV3()
		c, ok := mapvalues.LookupApplicationContext(oid)
		if !ok || c.Version != 3 || c.Name != "vcsgLocationCancellationContext-v3" || !c.OID.Equal(oid) || c.Source.Clause != "17.3.3" {
			t.Fatalf("context %+v", c)
		}
	}
	if _, ok := mapvalues.LookupApplicationContext(mapvalues.MapAc()); ok {
		t.Fatal("root is not a context")
	}
}
func TestTypedDescriptorSnapshots(t *testing.T) {
	first := mapvalues.Operations()
	before, _ := mapvalues.LookupOperation(first[0].Code)
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
	after, _ := mapvalues.LookupOperation(before.Code)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("shared operation metadata %+v %+v", before, after)
	}
	op := mapbindings.RegisterPasswordOperation()
	info := op.Info()
	info.Linked[0] = -1
	if op.Info().Linked[0] != mapvalues.GetPassword {
		t.Fatal("shared linked slice")
	}
	errors := mapvalues.Errors()
	prior, _ := mapvalues.LookupError(errors[0].Code)
	errors[0].Parameter.ASN1Name = "changed"
	again, _ := mapvalues.LookupError(prior.Code)
	if !reflect.DeepEqual(prior, again) {
		t.Fatal("shared error type ref")
	}
	ss := mapvalues.SSOperations()
	beforeSS, _ := mapvalues.LookupSSOperation(ss[0].Code)
	ss[0].Errors[0].Name = "changed"
	ss[0].Errors[0].Parameter.ASN1Name = "changed"
	afterSS, _ := mapvalues.LookupSSOperation(beforeSS.Code)
	if !reflect.DeepEqual(beforeSS, afterSS) {
		t.Fatal("shared SS metadata")
	}
	contexts := mapvalues.ApplicationContexts()
	oid := contexts[0].OID
	contexts[0].Name = "changed"
	context, _ := mapvalues.LookupApplicationContext(oid)
	if context.Name == "changed" {
		t.Fatal("shared context")
	}
}
func TestTypedErrorSelection(t *testing.T) {
	op := mapbindings.SendRoutingInfoForSMOperation()
	value := mapvalues.SendRoutingInfoForSMErrors{AbsentSubscriberSM: &mapvalues.ErrorValue[mapvalues.AbsentSubscriberSMParam]{Parameter: &mapvalues.AbsentSubscriberSMParam{}}}
	encoded, err := op.EncodeError(value)
	if err != nil || encoded.Code != mapvalues.AbsentSubscriberSM || !encoded.HasParameter {
		t.Fatalf("encode %+v %v", encoded, err)
	}
	decoded, err := op.DecodeError(encoded.Code, encoded.Parameter, encoded.HasParameter)
	if err != nil || decoded.AbsentSubscriberSM == nil || decoded.AbsentSubscriberSM.Parameter == nil {
		t.Fatalf("decode %+v %v", decoded, err)
	}
	if _, err := mapbindings.UpdateLocationOperation().DecodeError(encoded.Code, encoded.Parameter, true); err == nil {
		t.Fatal("disallowed error")
	}
	if _, err := op.EncodeError(mapvalues.SendRoutingInfoForSMErrors{}); err == nil {
		t.Fatal("zero arm")
	}
	value.SystemFailure = &mapvalues.ErrorValue[mapvalues.SystemFailureParam]{}
	if _, err := op.EncodeError(value); err == nil {
		t.Fatal("multiple arms")
	}
	if _, err := op.DecodeError(mapvalues.AbsentSubscriberSM, []byte{5, 0}, false); err == nil {
		t.Fatal("bytes on absent parameter")
	}
	if _, err := op.DecodeError(mapvalues.AbsentSubscriberSM, []byte{0x30, 0, 5, 0}, true); err == nil {
		t.Fatal("multiple TLVs")
	}
	absent, err := op.DecodeError(mapvalues.AbsentSubscriberSM, nil, false)
	if err != nil || absent.AbsentSubscriberSM == nil || absent.AbsentSubscriberSM.Parameter != nil {
		t.Fatalf("absence %+v %v", absent, err)
	}
	noArg, exists := mapbindings.ForwardCheckSSIndicationOperation().Argument()
	if exists {
		t.Fatal("manufactured argument")
	}
	if _, err := noArg.DecodeBER([]byte{5, 0}); err == nil {
		t.Fatal("NoParameter codec")
	}
	if _, err := mapbindings.SSNotifySSOperation().EncodeError(mapvalues.SSNotifySSErrors{}); err == nil {
		t.Fatal("zero arm operation")
	}
	plain := mapbindings.SSResourcesNotAvailableErrorDescriptor()
	if _, ok := plain.Parameter(); ok {
		t.Fatal("no PARAMETER is NULL")
	}
	ssop := mapbindings.SSProcessUnstructuredSSDataOperation()
	ssValue, err := ssop.DecodeError(34, nil, false)
	if err != nil || ssValue.SystemFailure == nil {
		t.Fatalf("SS mixed-origin absence %+v %v", ssValue, err)
	}
	if _, err := ssop.DecodeError(127, nil, false); err == nil {
		t.Fatal("SS unlisted member")
	}
	var zero mapbindings.Operation[mapvalues.NoParameter, mapvalues.NoParameter, mapvalues.SSNotifySSErrors]
	if _, err := zero.EncodeError(mapvalues.SSNotifySSErrors{}); err == nil {
		t.Fatal("zero descriptor")
	}
	primitive := mapbindings.SendIMSIOperation()
	argument, ok := primitive.Argument()
	if !ok {
		t.Fatal("primitive argument missing")
	}
	// TS 29.002 V19.1.0 §17.1.1: a known argument's nonminimal
	// header requires explicit tolerance, including byte-exact replay.
	wire := []byte{4, 0x81, 1, 0x91}
	checkProfile := func(violation ber.Violation, encoded bool) {
		t.Helper()
		if violation.Kind != ber.ProtocolRule || violation.Rule != (ber.RuleRef{Document: "3GPP TS 29.002", Edition: "V19.1.0", Clause: "17.1.1"}) || violation.Constraint != "TS 29.002 §17.1.1: short-length" || violation.Source != "MAP-CommonDataTypes.ISDN-AddressString" || violation.Path != "ISDN-AddressString" {
			t.Fatalf("primitive profile record: %+v", violation)
		}
		if encoded {
			if violation.Offset != nil || violation.OctetOffset != nil || violation.ChildIndexes != nil {
				t.Fatalf("primitive encode coordinates: %+v", violation)
			}
		} else if violation.Offset == nil || *violation.Offset != 0 || violation.OctetOffset != nil || violation.ChildIndexes != nil {
			t.Fatalf("primitive decode coordinates: %+v", violation)
		}
	}
	if _, err := argument.DecodeBER(wire); err == nil {
		t.Fatal("strict primitive argument accepted a nonminimal length")
	} else {
		var violation *ber.ValidationError
		var element *ber.ElementError
		if !errors.As(err, &violation) || !errors.As(err, &element) {
			t.Fatalf("strict primitive argument: %T %v", err, err)
		}
		checkProfile(violation.Violation, false)
		if element.Offset() != *violation.Offset || !reflect.DeepEqual(element.ChildIndexes(), violation.ChildIndexes) {
			t.Fatalf("primitive decode wrapper location: %v %+v", element, violation.Violation)
		}
	}
	var incoming ber.ViolationLog
	v, err := argument.DecodeBER(wire, ber.WithTolerance(&incoming))
	if err != nil {
		t.Fatal(err)
	}
	if rows := incoming.Snapshot(); len(rows) != 1 {
		t.Fatalf("primitive decode reports: %+v", rows)
	} else {
		checkProfile(rows[0], false)
	}
	if _, err := argument.EncodeBER(v); err == nil {
		t.Fatal("strict primitive argument replay accepted a profile violation")
	} else if violation, ok := err.(*ber.ValidationError); !ok {
		t.Fatalf("strict primitive argument replay: %T %v", err, err)
	} else {
		checkProfile(violation.Violation, true)
	}
	var outgoing ber.ViolationLog
	replayed, err := argument.EncodeBER(v, ber.WithTolerance(&outgoing))
	if err != nil || !bytes.Equal(wire, replayed) {
		t.Fatalf("primitive replay %x %v", replayed, err)
	}
	if rows := outgoing.Snapshot(); len(rows) != 1 {
		t.Fatalf("primitive encode reports: %+v", rows)
	} else {
		checkProfile(rows[0], true)
	}
	var log ber.ViolationLog
	bad, err := mapbindings.IMSICodec().DecodeBER([]byte{4, 1, 1}, ber.WithTolerance(&log))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mapbindings.IMSICodec().EncodeDER(bad); err == nil {
		t.Fatal("tolerant DER")
	}
}

func TestContextValuesAgainstApprovedTable(t *testing.T) {
	{
		oid := mapvalues.MapAc()
		if oid.String() != "0.4.0.0.1.0" {
			t.Fatalf("OID MapAc: %s", oid.String())
		}
	}
	{
		oid := mapvalues.NetworkLocUpContextV3()
		if oid.String() != "0.4.0.0.1.0.1.3" {
			t.Fatalf("OID NetworkLocUpContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.LocationCancellationContextV3()
		if oid.String() != "0.4.0.0.1.0.2.3" {
			t.Fatalf("OID LocationCancellationContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.RoamingNumberEnquiryContextV3()
		if oid.String() != "0.4.0.0.1.0.3.3" {
			t.Fatalf("OID RoamingNumberEnquiryContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.AuthenticationFailureReportContextV3()
		if oid.String() != "0.4.0.0.1.0.39.3" {
			t.Fatalf("OID AuthenticationFailureReportContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.LocationInfoRetrievalContextV3()
		if oid.String() != "0.4.0.0.1.0.5.3" {
			t.Fatalf("OID LocationInfoRetrievalContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.ResetContextV3()
		if oid.String() != "0.4.0.0.1.0.10.3" {
			t.Fatalf("OID ResetContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.HandoverControlContextV3()
		if oid.String() != "0.4.0.0.1.0.11.3" {
			t.Fatalf("OID HandoverControlContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.EquipmentMngtContextV3()
		if oid.String() != "0.4.0.0.1.0.13.3" {
			t.Fatalf("OID EquipmentMngtContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.InfoRetrievalContextV3()
		if oid.String() != "0.4.0.0.1.0.14.3" {
			t.Fatalf("OID InfoRetrievalContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.InterVlrInfoRetrievalContextV3()
		if oid.String() != "0.4.0.0.1.0.15.3" {
			t.Fatalf("OID InterVlrInfoRetrievalContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.SubscriberDataMngtContextV3()
		if oid.String() != "0.4.0.0.1.0.16.3" {
			t.Fatalf("OID SubscriberDataMngtContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.TracingContextV3()
		if oid.String() != "0.4.0.0.1.0.17.3" {
			t.Fatalf("OID TracingContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.NetworkFunctionalSsContextV2()
		if oid.String() != "0.4.0.0.1.0.18.2" {
			t.Fatalf("OID NetworkFunctionalSsContextV2: %s", oid.String())
		}
	}
	{
		oid := mapvalues.NetworkUnstructuredSsContextV2()
		if oid.String() != "0.4.0.0.1.0.19.2" {
			t.Fatalf("OID NetworkUnstructuredSsContextV2: %s", oid.String())
		}
	}
	{
		oid := mapvalues.ShortMsgGatewayContextV3()
		if oid.String() != "0.4.0.0.1.0.20.3" {
			t.Fatalf("OID ShortMsgGatewayContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.ShortMsgMORelayContextV3()
		if oid.String() != "0.4.0.0.1.0.21.3" {
			t.Fatalf("OID ShortMsgMORelayContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.ShortMsgAlertContextV2()
		if oid.String() != "0.4.0.0.1.0.23.2" {
			t.Fatalf("OID ShortMsgAlertContextV2: %s", oid.String())
		}
	}
	{
		oid := mapvalues.MwdMngtContextV3()
		if oid.String() != "0.4.0.0.1.0.24.3" {
			t.Fatalf("OID MwdMngtContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.ShortMsgMTRelayContextV3()
		if oid.String() != "0.4.0.0.1.0.25.3" {
			t.Fatalf("OID ShortMsgMTRelayContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.ShortMsgMTRelayVGCSContextV3()
		if oid.String() != "0.4.0.0.1.0.41.3" {
			t.Fatalf("OID ShortMsgMTRelayVGCSContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.ImsiRetrievalContextV2()
		if oid.String() != "0.4.0.0.1.0.26.2" {
			t.Fatalf("OID ImsiRetrievalContextV2: %s", oid.String())
		}
	}
	{
		oid := mapvalues.MsPurgingContextV3()
		if oid.String() != "0.4.0.0.1.0.27.3" {
			t.Fatalf("OID MsPurgingContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.SubscriberInfoEnquiryContextV3()
		if oid.String() != "0.4.0.0.1.0.28.3" {
			t.Fatalf("OID SubscriberInfoEnquiryContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.AnyTimeInfoEnquiryContextV3()
		if oid.String() != "0.4.0.0.1.0.29.3" {
			t.Fatalf("OID AnyTimeInfoEnquiryContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.CallControlTransferContextV4()
		if oid.String() != "0.4.0.0.1.0.6.4" {
			t.Fatalf("OID CallControlTransferContextV4: %s", oid.String())
		}
	}
	{
		oid := mapvalues.SsInvocationNotificationContextV3()
		if oid.String() != "0.4.0.0.1.0.36.3" {
			t.Fatalf("OID SsInvocationNotificationContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.GroupCallControlContextV3()
		if oid.String() != "0.4.0.0.1.0.31.3" {
			t.Fatalf("OID GroupCallControlContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.GroupCallInfoRetrievalContextV3()
		if oid.String() != "0.4.0.0.1.0.45.3" {
			t.Fatalf("OID GroupCallInfoRetrievalContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.GprsLocationUpdateContextV3()
		if oid.String() != "0.4.0.0.1.0.32.3" {
			t.Fatalf("OID GprsLocationUpdateContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.GprsLocationInfoRetrievalContextV4()
		if oid.String() != "0.4.0.0.1.0.33.4" {
			t.Fatalf("OID GprsLocationInfoRetrievalContextV4: %s", oid.String())
		}
	}
	{
		oid := mapvalues.FailureReportContextV3()
		if oid.String() != "0.4.0.0.1.0.34.3" {
			t.Fatalf("OID FailureReportContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.GprsNotifyContextV3()
		if oid.String() != "0.4.0.0.1.0.35.3" {
			t.Fatalf("OID GprsNotifyContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.ReportingContextV3()
		if oid.String() != "0.4.0.0.1.0.7.3" {
			t.Fatalf("OID ReportingContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.CallCompletionContextV3()
		if oid.String() != "0.4.0.0.1.0.8.3" {
			t.Fatalf("OID CallCompletionContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.IstAlertingContextV3()
		if oid.String() != "0.4.0.0.1.0.4.3" {
			t.Fatalf("OID IstAlertingContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.ServiceTerminationContextV3()
		if oid.String() != "0.4.0.0.1.0.9.3" {
			t.Fatalf("OID ServiceTerminationContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.LocationSvcGatewayContextV3()
		if oid.String() != "0.4.0.0.1.0.37.3" {
			t.Fatalf("OID LocationSvcGatewayContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.LocationSvcEnquiryContextV3()
		if oid.String() != "0.4.0.0.1.0.38.3" {
			t.Fatalf("OID LocationSvcEnquiryContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.MmEventReportingContextV3()
		if oid.String() != "0.4.0.0.1.0.42.3" {
			t.Fatalf("OID MmEventReportingContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.AnyTimeInfoHandlingContextV3()
		if oid.String() != "0.4.0.0.1.0.43.3" {
			t.Fatalf("OID AnyTimeInfoHandlingContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.SubscriberDataModificationNotificationContextV3()
		if oid.String() != "0.4.0.0.1.0.22.3" {
			t.Fatalf("OID SubscriberDataModificationNotificationContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.ResourceManagementContextV3()
		if oid.String() != "0.4.0.0.1.0.44.3" {
			t.Fatalf("OID ResourceManagementContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.VcsgLocationUpdateContextV3()
		if oid.String() != "0.4.0.0.1.0.46.3" {
			t.Fatalf("OID VcsgLocationUpdateContextV3: %s", oid.String())
		}
	}
	{
		oid := mapvalues.VcsgLocationCancellationContextV3()
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
		info, ok := mapvalues.LookupSSError(mapvalues.SSErrorCode(127))
		if !ok || info.Name != "resourcesNotAvailable" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "resourcesNotAvailable" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := mapvalues.LookupSSError(mapvalues.SSErrorCode(126))
		if !ok || info.Name != "maxNumberOfMPTY-ParticipantsExceeded" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "maxNumberOfMPTY-ParticipantsExceeded" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := mapvalues.LookupSSError(mapvalues.SSErrorCode(125))
		if !ok || info.Name != "invalidDeflectedToNumber" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "invalidDeflectedToNumber" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := mapvalues.LookupSSError(mapvalues.SSErrorCode(124))
		if !ok || info.Name != "specialServiceCode" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "specialServiceCode" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := mapvalues.LookupSSError(mapvalues.SSErrorCode(123))
		if !ok || info.Name != "deflectionToServedSubscriber" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "deflectionToServedSubscriber" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := mapvalues.LookupSSError(mapvalues.SSErrorCode(122))
		if !ok || info.Name != "rejectedByNetwork" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "rejectedByNetwork" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := mapvalues.LookupSSError(mapvalues.SSErrorCode(121))
		if !ok || info.Name != "rejectedByUser" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "rejectedByUser" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := mapvalues.LookupSSError(mapvalues.SSErrorCode(120))
		if !ok || info.Name != "lcs-invalidPru" || info.Source.Module != "SS-Errors" || info.Source.Assignment != "lcs-invalidPru" || info.Source.SHA256 != "b81d2a668e33702414eec4d9210bd4922f1104ccc4384cb6d8d3301ce8fa129e" || info.Source.Edition != "19.4.0" || info.Source.Document != "3GPP TS 24.080" || info.ParameterOptional != nil {
			t.Fatalf("supplemental metadata %+v", info)
		}
		if info.Parameter != nil {
			t.Fatal("invented parameter type")
		}
	}
	{
		info, ok := mapvalues.LookupSSError(mapvalues.SSErrorCode(119))
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

func TestConstructorValidityAndCallbacks(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		calls := 0
		var decode func([]byte, ...ber.DecodeOption) (int, error)
		var encode func(int, ...ber.EncodeOption) ([]byte, error)
		var der func(int) ([]byte, error)
		if mask&1 != 0 {
			decode = func([]byte, ...ber.DecodeOption) (int, error) { calls++; return 7, nil }
		}
		if mask&2 != 0 {
			encode = func(int, ...ber.EncodeOption) ([]byte, error) { calls++; return []byte{1}, nil }
		}
		if mask&4 != 0 {
			der = func(int) ([]byte, error) { calls++; return []byte{2}, nil }
		}
		codec := mapvalues.NewValueCodec(decode, encode, der)
		if codec.Valid() != (mask == 7) {
			t.Fatalf("mask %d: validity", mask)
		}
		value, decodeErr := codec.DecodeBER(nil)
		wire, encodeErr := codec.EncodeBER(7)
		canonical, derErr := codec.EncodeDER(7)
		if mask != 7 {
			if !errors.Is(decodeErr, ber.ErrInvalidCodec) || !errors.Is(encodeErr, ber.ErrInvalidCodec) || !errors.Is(derErr, ber.ErrInvalidCodec) || calls != 0 {
				t.Fatalf("mask %d: invalid codec dispatched callbacks", mask)
			}
		} else if decodeErr != nil || encodeErr != nil || derErr != nil || calls != 3 || value != 7 || !bytes.Equal(wire, []byte{1}) || !bytes.Equal(canonical, []byte{2}) {
			t.Fatal("constructor callback mismatch")
		}
	}
}
