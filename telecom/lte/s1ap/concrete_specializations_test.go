// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

func tAIItemIEFieldFreshMust(v s33.TAIItemIEField, err error) s33.TAIItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func tAIItemIEValueERABIEContainerListAPERValueFreshMust(v s33.TAIItemIEValueERABIEContainerListAPERValue, err error) s33.TAIItemIEValueERABIEContainerListAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func sliceByteFreshMust(v []byte,

	err error) []byte {
	if err != nil {
		panic(err)
	}
	return v
}
func tAIItemIEFieldAPERValueFreshMust(v s33.TAIItemIEFieldAPERValue, err error) s33.TAIItemIEFieldAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func criticalityDiagnosticsExtIEsExtFieldFreshMust(v s07.CriticalityDiagnosticsExtIEsExtField, err error) s07.CriticalityDiagnosticsExtIEsExtField {
	if err != nil {
		panic(err)
	}
	return v
}
func criticalityDiagnosticsExtIEsExtContainerAPERValueFreshMust(v s07.CriticalityDiagnosticsExtIEsExtContainerAPERValue, err error) s07.CriticalityDiagnosticsExtIEsExtContainerAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func privateIEIDFreshMust(v s20.PrivateIEID,

	err error) s20.PrivateIEID {
	if err != nil {
		panic(err)
	}
	return v
}
func privateMessageIEsValuePrivateIEFieldFreshMust(v s25.PrivateMessageIEsValuePrivateIEField, err error) s25.PrivateMessageIEsValuePrivateIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func privateMessageIEsValuePrivateIEContainerAPERValueFreshMust(v s25.PrivateMessageIEsValuePrivateIEContainerAPERValue, err error) s25.PrivateMessageIEsValuePrivateIEContainerAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func errorIndicationIEFieldConsistencyMust(value s28.ErrorIndicationIEField, err error) s28.ErrorIndicationIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func eRABInformationListItemExtIEsExtFieldConsistencyMust(value s28.ERABInformationListItemExtIEsExtField, err error) s28.ERABInformationListItemExtIEsExtField {
	if err != nil {
		panic(err)
	}
	return value
}
func criticalityDiagnosticsExtIEsExtFieldConsistencyMust(value s07.CriticalityDiagnosticsExtIEsExtField, err error) s07.CriticalityDiagnosticsExtIEsExtField {
	if err != nil {
		panic(err)
	}
	return value
}
func sliceByteConsistencyMust(value []byte,

	err error) []byte {
	if err != nil {
		panic(err)
	}
	return value
}
func errorIndicationIEFieldAPERValueConsistencyMust(value s28.ErrorIndicationIEFieldAPERValue, err error) s28.ErrorIndicationIEFieldAPERValue {
	if err != nil {
		panic(err)
	}
	return value
}
func eRABInformationListItemExtIEsExtFieldAPERValueConsistencyMust(value s28.ERABInformationListItemExtIEsExtFieldAPERValue, err error) s28.ERABInformationListItemExtIEsExtFieldAPERValue {
	if err != nil {
		panic(err)
	}
	return value
}
func resetAcknowledgeEnvelopeMust(v s44.ResetAcknowledge,

	err error) s44.ResetAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func causeEnvelopeMust(v s14.Cause,

	err error) s14.Cause {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupFailureEnvelopeMust(v s26.S1SetupFailure,

	err error) s26.S1SetupFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupFailureIEFieldEnvelopeMust(v s23.S1SetupFailureIEField, err error) s23.S1SetupFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func initiatingMessageEnvelopeMust(v s51.InitiatingMessage,

	err error) s51.InitiatingMessage {
	if err != nil {
		panic(err)
	}
	return v
}
func errorIndicationEnvelopeMust(v s28.ErrorIndication,

	err error) s28.ErrorIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func successfulOutcomeEnvelopeMust(v s50.SuccessfulOutcome,

	err error) s50.SuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return v
}
func unsuccessfulOutcomeEnvelopeMust(v s36.UnsuccessfulOutcome,

	err error) s36.UnsuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return v
}
func sliceByteEnvelopeMust(v []byte,

	err error) []byte {
	if err != nil {
		panic(err)
	}
	return v
}
func privateIEIDEnvelopeMust(v s20.PrivateIEID,

	err error) s20.PrivateIEID {
	if err != nil {
		panic(err)
	}
	return v
}
func privateMessageIEsValuePrivateIEFieldEnvelopeMust(v s25.PrivateMessageIEsValuePrivateIEField, err error) s25.PrivateMessageIEsValuePrivateIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func objectIdentifierEnvelopeMust(v runtime.ObjectIdentifier,

	err error) runtime.ObjectIdentifier {
	if err != nil {
		panic(err)
	}
	return v
}
func s1APPDUFreshMust(v s52.S1APPDU,

	err error) s52.S1APPDU {
	if err != nil {
		panic(err)
	}
	return v
}
func initiatingMessageFreshMust(v s51.InitiatingMessage,

	err error) s51.InitiatingMessage {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequiredFreshMust(v s34.HandoverRequired,

	err error) s34.HandoverRequired {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequiredIEFieldFreshMust(v s34.HandoverRequiredIEField, err error) s34.HandoverRequiredIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func causeFreshMust(v s14.Cause,

	err error) s14.Cause {
	if err != nil {
		panic(err)
	}
	return v
}
func targetIDFreshMust(v s34.TargetID,

	err error) s34.TargetID {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBIDFreshMust(v s15.ENBID,

	err error) s15.ENBID {
	if err != nil {
		panic(err)
	}
	return v
}
func successfulOutcomeFreshMust(v s50.SuccessfulOutcome,

	err error) s50.SuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCommandFreshMust(v s40.HandoverCommand,

	err error) s40.HandoverCommand {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCommandIEFieldFreshMust(v s40.HandoverCommandIEField, err error) s40.HandoverCommandIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func unsuccessfulOutcomeFreshMust(v s36.UnsuccessfulOutcome,

	err error) s36.UnsuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverPreparationFailureFreshMust(v s25.HandoverPreparationFailure,

	err error) s25.HandoverPreparationFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverPreparationFailureIEFieldFreshMust(v s22.HandoverPreparationFailureIEField, err error) s22.HandoverPreparationFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequestFreshMust(v s48.HandoverRequest,

	err error) s48.HandoverRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequestIEFieldFreshMust(v s47.HandoverRequestIEField, err error) s47.HandoverRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeSetupItemHOReqIEFieldFreshMust(v s29.ERABToBeSetupItemHOReqIEField, err error) s29.ERABToBeSetupItemHOReqIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequestAcknowledgeFreshMust(v s39.HandoverRequestAcknowledge,

	err error) s39.HandoverRequestAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequestAcknowledgeIEFieldFreshMust(v s38.HandoverRequestAcknowledgeIEField, err error) s38.HandoverRequestAcknowledgeIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABAdmittedItemIEFieldFreshMust(v s15.ERABAdmittedItemIEField, err error) s15.ERABAdmittedItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverFailureFreshMust(v s25.HandoverFailure,

	err error) s25.HandoverFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverFailureIEFieldFreshMust(v s22.HandoverFailureIEField, err error) s22.HandoverFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestFreshMust(v s41.PathSwitchRequest,

	err error) s41.PathSwitchRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestIEFieldFreshMust(v s40.PathSwitchRequestIEField, err error) s40.PathSwitchRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeSwitchedDLItemIEFieldFreshMust(v s30.ERABToBeSwitchedDLItemIEField, err error) s30.ERABToBeSwitchedDLItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestAcknowledgeFreshMust(v s47.PathSwitchRequestAcknowledge,

	err error) s47.PathSwitchRequestAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestAcknowledgeIEFieldFreshMust(v s46.PathSwitchRequestAcknowledgeIEField, err error) s46.PathSwitchRequestAcknowledgeIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestFailureFreshMust(v s26.PathSwitchRequestFailure,

	err error) s26.PathSwitchRequestFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestFailureIEFieldFreshMust(v s23.PathSwitchRequestFailureIEField, err error) s23.PathSwitchRequestFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABSetupRequestFreshMust(v s40.ERABSetupRequest,

	err error) s40.ERABSetupRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABSetupRequestIEFieldFreshMust(v s40.ERABSetupRequestIEField, err error) s40.ERABSetupRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeSetupItemBearerSUReqIEFieldFreshMust(v s29.ERABToBeSetupItemBearerSUReqIEField, err error) s29.ERABToBeSetupItemBearerSUReqIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABSetupResponseFreshMust(v s46.ERABSetupResponse,

	err error) s46.ERABSetupResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABSetupResponseIEFieldFreshMust(v s45.ERABSetupResponseIEField, err error) s45.ERABSetupResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModifyRequestFreshMust(v s40.ERABModifyRequest,

	err error) s40.ERABModifyRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModifyRequestIEFieldFreshMust(v s40.ERABModifyRequestIEField, err error) s40.ERABModifyRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeModifiedItemBearerModReqIEFieldFreshMust(v s25.ERABToBeModifiedItemBearerModReqIEField, err error) s25.ERABToBeModifiedItemBearerModReqIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModifyResponseFreshMust(v s45.ERABModifyResponse,

	err error) s45.ERABModifyResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModifyResponseIEFieldFreshMust(v s44.ERABModifyResponseIEField, err error) s44.ERABModifyResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseCommandFreshMust(v s39.ERABReleaseCommand,

	err error) s39.ERABReleaseCommand {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseCommandIEFieldFreshMust(v s39.ERABReleaseCommandIEField, err error) s39.ERABReleaseCommandIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABItemIEFieldFreshMust(v s16.ERABItemIEField, err error) s16.ERABItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseResponseFreshMust(v s46.ERABReleaseResponse,

	err error) s46.ERABReleaseResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseResponseIEFieldFreshMust(v s45.ERABReleaseResponseIEField, err error) s45.ERABReleaseResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupRequestFreshMust(v s48.InitialContextSetupRequest,

	err error) s48.InitialContextSetupRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupRequestIEFieldFreshMust(v s48.InitialContextSetupRequestIEField, err error) s48.InitialContextSetupRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeSetupItemCtxtSUReqIEFieldFreshMust(v s29.ERABToBeSetupItemCtxtSUReqIEField, err error) s29.ERABToBeSetupItemCtxtSUReqIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupResponseFreshMust(v s39.InitialContextSetupResponse,

	err error) s39.InitialContextSetupResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupResponseIEFieldFreshMust(v s39.InitialContextSetupResponseIEField, err error) s39.InitialContextSetupResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABSetupItemCtxtSUResIEFieldFreshMust(v s16.ERABSetupItemCtxtSUResIEField, err error) s16.ERABSetupItemCtxtSUResIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupFailureFreshMust(v s25.InitialContextSetupFailure,

	err error) s25.InitialContextSetupFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupFailureIEFieldFreshMust(v s22.InitialContextSetupFailureIEField, err error) s22.InitialContextSetupFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCancelFreshMust(v s25.HandoverCancel,

	err error) s25.HandoverCancel {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCancelIEFieldFreshMust(v s18.HandoverCancelIEField, err error) s18.HandoverCancelIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCancelAcknowledgeFreshMust(v s25.HandoverCancelAcknowledge,

	err error) s25.HandoverCancelAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCancelAcknowledgeIEFieldFreshMust(v s22.HandoverCancelAcknowledgeIEField, err error) s22.HandoverCancelAcknowledgeIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func killRequestFreshMust(v s33.KillRequest,

	err error) s33.KillRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func killRequestIEFieldFreshMust(v s32.KillRequestIEField, err error) s32.KillRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func killResponseFreshMust(v s33.KillResponse,

	err error) s33.KillResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func killResponseIEFieldFreshMust(v s32.KillResponseIEField, err error) s32.KillResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func resetFreshMust(v s36.Reset,

	err error) s36.Reset {
	if err != nil {
		panic(err)
	}
	return v
}
func resetIEFieldFreshMust(v s36.ResetIEField, err error) s36.ResetIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func resetTypeFreshMust(v s35.ResetType,

	err error) s35.ResetType {
	if err != nil {
		panic(err)
	}
	return v
}
func resetAcknowledgeFreshMust(v s44.ResetAcknowledge,

	err error) s44.ResetAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupRequestFreshMust(v s43.S1SetupRequest,

	err error) s43.S1SetupRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupRequestIEFieldFreshMust(v s43.S1SetupRequestIEField, err error) s43.S1SetupRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupResponseFreshMust(v s43.S1SetupResponse,

	err error) s43.S1SetupResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupResponseIEFieldFreshMust(v s43.S1SetupResponseIEField, err error) s43.S1SetupResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupFailureFreshMust(v s26.S1SetupFailure,

	err error) s26.S1SetupFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupFailureIEFieldFreshMust(v s23.S1SetupFailureIEField, err error) s23.S1SetupFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationRequestFreshMust(v s47.UEContextModificationRequest,

	err error) s47.UEContextModificationRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationRequestIEFieldFreshMust(v s46.UEContextModificationRequestIEField, err error) s46.UEContextModificationRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationResponseFreshMust(v s36.UEContextModificationResponse,

	err error) s36.UEContextModificationResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationResponseIEFieldFreshMust(v s23.UEContextModificationResponseIEField, err error) s23.UEContextModificationResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationFailureFreshMust(v s36.UEContextModificationFailure,

	err error) s36.UEContextModificationFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationFailureIEFieldFreshMust(v s23.UEContextModificationFailureIEField, err error) s23.UEContextModificationFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseCommandFreshMust(v s37.UEContextReleaseCommand,

	err error) s37.UEContextReleaseCommand {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseCommandIEFieldFreshMust(v s37.UEContextReleaseCommandIEField, err error) s37.UEContextReleaseCommandIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uES1APIDsFreshMust(v s37.UES1APIDs,

	err error) s37.UES1APIDs {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseCompleteFreshMust(v s46.UEContextReleaseComplete,

	err error) s46.UEContextReleaseComplete {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseCompleteIEFieldFreshMust(v s45.UEContextReleaseCompleteIEField, err error) s45.UEContextReleaseCompleteIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBConfigurationUpdateFreshMust(v s43.ENBConfigurationUpdate,

	err error) s43.ENBConfigurationUpdate {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBConfigurationUpdateAcknowledgeFreshMust(v s24.ENBConfigurationUpdateAcknowledge,

	err error) s24.ENBConfigurationUpdateAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBConfigurationUpdateFailureFreshMust(v s24.ENBConfigurationUpdateFailure,

	err error) s24.ENBConfigurationUpdateFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBConfigurationUpdateFailureIEFieldFreshMust(v s22.ENBConfigurationUpdateFailureIEField, err error) s22.ENBConfigurationUpdateFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEConfigurationUpdateFreshMust(v s43.MMEConfigurationUpdate,

	err error) s43.MMEConfigurationUpdate {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEConfigurationUpdateAcknowledgeFreshMust(v s25.MMEConfigurationUpdateAcknowledge,

	err error) s25.MMEConfigurationUpdateAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEConfigurationUpdateFailureFreshMust(v s25.MMEConfigurationUpdateFailure,

	err error) s25.MMEConfigurationUpdateFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEConfigurationUpdateFailureIEFieldFreshMust(v s23.MMEConfigurationUpdateFailureIEField, err error) s23.MMEConfigurationUpdateFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func writeReplaceWarningRequestFreshMust(v s50.WriteReplaceWarningRequest,

	err error) s50.WriteReplaceWarningRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func writeReplaceWarningRequestIEFieldFreshMust(v s33.WriteReplaceWarningRequestIEField, err error) s33.WriteReplaceWarningRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func writeReplaceWarningResponseFreshMust(v s50.WriteReplaceWarningResponse,

	err error) s50.WriteReplaceWarningResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func writeReplaceWarningResponseIEFieldFreshMust(v s32.WriteReplaceWarningResponseIEField, err error) s32.WriteReplaceWarningResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverNotifyFreshMust(v s35.HandoverNotify,

	err error) s35.HandoverNotify {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverNotifyIEFieldFreshMust(v s35.HandoverNotifyIEField, err error) s35.HandoverNotifyIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseIndicationFreshMust(v s45.ERABReleaseIndication,

	err error) s45.ERABReleaseIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseIndicationIEFieldFreshMust(v s44.ERABReleaseIndicationIEField, err error) s44.ERABReleaseIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pagingFreshMust(v s49.Paging,

	err error) s49.Paging {
	if err != nil {
		panic(err)
	}
	return v
}
func pagingIEFieldFreshMust(v s49.PagingIEField, err error) s49.PagingIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEPagingIDFreshMust(v s28.UEPagingID,

	err error) s28.UEPagingID {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkNASTransportFreshMust(v s42.DownlinkNASTransport,

	err error) s42.DownlinkNASTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkNASTransportIEFieldFreshMust(v s42.DownlinkNASTransportIEField, err error) s42.DownlinkNASTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func initialUEMessageFreshMust(v s35.InitialUEMessage,

	err error) s35.InitialUEMessage {
	if err != nil {
		panic(err)
	}
	return v
}
func initialUEMessageIEFieldFreshMust(v s35.InitialUEMessageIEField, err error) s35.InitialUEMessageIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkNASTransportFreshMust(v s44.UplinkNASTransport,

	err error) s44.UplinkNASTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkNASTransportIEFieldFreshMust(v s32.UplinkNASTransportIEField, err error) s32.UplinkNASTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func errorIndicationFreshMust(v s28.ErrorIndication,

	err error) s28.ErrorIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func nASNonDeliveryIndicationFreshMust(v s25.NASNonDeliveryIndication,

	err error) s25.NASNonDeliveryIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func nASNonDeliveryIndicationIEFieldFreshMust(v s19.NASNonDeliveryIndicationIEField, err error) s19.NASNonDeliveryIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseRequestFreshMust(v s42.UEContextReleaseRequest,

	err error) s42.UEContextReleaseRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseRequestIEFieldFreshMust(v s42.UEContextReleaseRequestIEField, err error) s42.UEContextReleaseRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkS1cdma2000tunnellingFreshMust(v s40.DownlinkS1cdma2000tunnelling,

	err error) s40.DownlinkS1cdma2000tunnelling {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkS1cdma2000tunnellingIEFieldFreshMust(v s40.DownlinkS1cdma2000tunnellingIEField, err error) s40.DownlinkS1cdma2000tunnellingIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkS1cdma2000tunnellingFreshMust(v s44.UplinkS1cdma2000tunnelling,

	err error) s44.UplinkS1cdma2000tunnelling {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkS1cdma2000tunnellingIEFieldFreshMust(v s21.UplinkS1cdma2000tunnellingIEField, err error) s21.UplinkS1cdma2000tunnellingIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uECapabilityInfoIndicationFreshMust(v s36.UECapabilityInfoIndication,

	err error) s36.UECapabilityInfoIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func uECapabilityInfoIndicationIEFieldFreshMust(v s12.UECapabilityInfoIndicationIEField, err error) s12.UECapabilityInfoIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBStatusTransferFreshMust(v s24.ENBStatusTransfer,

	err error) s24.ENBStatusTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBStatusTransferIEFieldFreshMust(v s21.ENBStatusTransferIEField, err error) s21.ENBStatusTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func bearersSubjectToStatusTransferItemIEFieldFreshMust(v s21.BearersSubjectToStatusTransferItemIEField, err error) s21.BearersSubjectToStatusTransferItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEStatusTransferFreshMust(v s25.MMEStatusTransfer,

	err error) s25.MMEStatusTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEStatusTransferIEFieldFreshMust(v s21.MMEStatusTransferIEField, err error) s21.MMEStatusTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func deactivateTraceFreshMust(v s15.DeactivateTrace,

	err error) s15.DeactivateTrace {
	if err != nil {
		panic(err)
	}
	return v
}
func deactivateTraceIEFieldFreshMust(v s08.DeactivateTraceIEField, err error) s08.DeactivateTraceIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func traceStartFreshMust(v s48.TraceStart,

	err error) s48.TraceStart {
	if err != nil {
		panic(err)
	}
	return v
}
func traceStartIEFieldFreshMust(v s48.TraceStartIEField, err error) s48.TraceStartIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func traceFailureIndicationFreshMust(v s34.TraceFailureIndication,

	err error) s34.TraceFailureIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func traceFailureIndicationIEFieldFreshMust(v s20.TraceFailureIndicationIEField, err error) s20.TraceFailureIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func cellTrafficTraceFreshMust(v s21.CellTrafficTrace,

	err error) s21.CellTrafficTrace {
	if err != nil {
		panic(err)
	}
	return v
}
func cellTrafficTraceIEFieldFreshMust(v s17.CellTrafficTraceIEField, err error) s17.CellTrafficTraceIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportingControlFreshMust(v s26.LocationReportingControl,

	err error) s26.LocationReportingControl {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportingControlIEFieldFreshMust(v s26.LocationReportingControlIEField, err error) s26.LocationReportingControlIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportingFailureIndicationFreshMust(v s25.LocationReportingFailureIndication,

	err error) s25.LocationReportingFailureIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportingFailureIndicationIEFieldFreshMust(v s18.LocationReportingFailureIndicationIEField, err error) s18.LocationReportingFailureIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportFreshMust(v s33.LocationReport,

	err error) s33.LocationReport {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportIEFieldFreshMust(v s31.LocationReportIEField, err error) s31.LocationReportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func overloadStartFreshMust(v s41.OverloadStart,

	err error) s41.OverloadStart {
	if err != nil {
		panic(err)
	}
	return v
}
func overloadStartIEFieldFreshMust(v s41.OverloadStartIEField, err error) s41.OverloadStartIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func overloadResponseFreshMust(v s20.OverloadResponse,

	err error) s20.OverloadResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func overloadStopFreshMust(v s41.OverloadStop,

	err error) s41.OverloadStop {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBDirectInformationTransferFreshMust(v s34.ENBDirectInformationTransfer,

	err error) s34.ENBDirectInformationTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBDirectInformationTransferIEFieldFreshMust(v s33.ENBDirectInformationTransferIEField, err error) s33.ENBDirectInformationTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func interSystemInformationTransferTypeFreshMust(v s33.InterSystemInformationTransferType,

	err error) s33.InterSystemInformationTransferType {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEDirectInformationTransferFreshMust(v s34.MMEDirectInformationTransfer,

	err error) s34.MMEDirectInformationTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEDirectInformationTransferIEFieldFreshMust(v s33.MMEDirectInformationTransferIEField, err error) s33.MMEDirectInformationTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBConfigurationTransferFreshMust(v s51.ENBConfigurationTransfer,

	err error) s51.ENBConfigurationTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEConfigurationTransferFreshMust(v s51.MMEConfigurationTransfer,

	err error) s51.MMEConfigurationTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func privateMessageFreshMust(v s26.PrivateMessage,

	err error) s26.PrivateMessage {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityMatchRequestFreshMust(v s36.UERadioCapabilityMatchRequest,

	err error) s36.UERadioCapabilityMatchRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityMatchRequestIEFieldFreshMust(v s12.UERadioCapabilityMatchRequestIEField, err error) s12.UERadioCapabilityMatchRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityMatchResponseFreshMust(v s36.UERadioCapabilityMatchResponse,

	err error) s36.UERadioCapabilityMatchResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityMatchResponseIEFieldFreshMust(v s24.UERadioCapabilityMatchResponseIEField, err error) s24.UERadioCapabilityMatchResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModificationIndicationFreshMust(v s45.ERABModificationIndication,

	err error) s45.ERABModificationIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModificationIndicationIEFieldFreshMust(v s44.ERABModificationIndicationIEField, err error) s44.ERABModificationIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeModifiedItemBearerModIndIEFieldFreshMust(v s17.ERABToBeModifiedItemBearerModIndIEField, err error) s17.ERABToBeModifiedItemBearerModIndIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModificationConfirmFreshMust(v s39.ERABModificationConfirm,

	err error) s39.ERABModificationConfirm {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModificationConfirmIEFieldFreshMust(v s39.ERABModificationConfirmIEField, err error) s39.ERABModificationConfirmIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationIndicationFreshMust(v s36.UEContextModificationIndication,

	err error) s36.UEContextModificationIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationIndicationIEFieldFreshMust(v s21.UEContextModificationIndicationIEField, err error) s21.UEContextModificationIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationConfirmFreshMust(v s36.UEContextModificationConfirm,

	err error) s36.UEContextModificationConfirm {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationConfirmIEFieldFreshMust(v s23.UEContextModificationConfirmIEField, err error) s23.UEContextModificationConfirmIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextSuspendRequestFreshMust(v s46.UEContextSuspendRequest,

	err error) s46.UEContextSuspendRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextSuspendRequestIEFieldFreshMust(v s45.UEContextSuspendRequestIEField, err error) s45.UEContextSuspendRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextSuspendResponseFreshMust(v s36.UEContextSuspendResponse,

	err error) s36.UEContextSuspendResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextSuspendResponseIEFieldFreshMust(v s28.UEContextSuspendResponseIEField, err error) s28.UEContextSuspendResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeRequestFreshMust(v s38.UEContextResumeRequest,

	err error) s38.UEContextResumeRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeRequestIEFieldFreshMust(v s38.UEContextResumeRequestIEField, err error) s38.UEContextResumeRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeResponseFreshMust(v s38.UEContextResumeResponse,

	err error) s38.UEContextResumeResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeResponseIEFieldFreshMust(v s38.UEContextResumeResponseIEField, err error) s38.UEContextResumeResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeFailureFreshMust(v s36.UEContextResumeFailure,

	err error) s36.UEContextResumeFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeFailureIEFieldFreshMust(v s23.UEContextResumeFailureIEField, err error) s23.UEContextResumeFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityIDMappingRequestFreshMust(v s36.UERadioCapabilityIDMappingRequest,

	err error) s36.UERadioCapabilityIDMappingRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityIDMappingRequestIEFieldFreshMust(v s12.UERadioCapabilityIDMappingRequestIEField, err error) s12.UERadioCapabilityIDMappingRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityIDMappingResponseFreshMust(v s36.UERadioCapabilityIDMappingResponse,

	err error) s36.UERadioCapabilityIDMappingResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityIDMappingResponseIEFieldFreshMust(v s23.UERadioCapabilityIDMappingResponseIEField, err error) s23.UERadioCapabilityIDMappingResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func s1RemovalRequestFreshMust(v s26.S1RemovalRequest,

	err error) s26.S1RemovalRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func s1RemovalRequestIEFieldFreshMust(v s20.S1RemovalRequestIEField, err error) s20.S1RemovalRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func s1RemovalResponseFreshMust(v s26.S1RemovalResponse,

	err error) s26.S1RemovalResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func s1RemovalFailureFreshMust(v s26.S1RemovalFailure,

	err error) s26.S1RemovalFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func s1RemovalFailureIEFieldFreshMust(v s23.S1RemovalFailureIEField, err error) s23.S1RemovalFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkUEAssociatedLPPaTransportFreshMust(v s15.DownlinkUEAssociatedLPPaTransport,

	err error) s15.DownlinkUEAssociatedLPPaTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkUEAssociatedLPPaTransportIEFieldFreshMust(v s08.DownlinkUEAssociatedLPPaTransportIEField, err error) s08.DownlinkUEAssociatedLPPaTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkUEAssociatedLPPaTransportFreshMust(v s44.UplinkUEAssociatedLPPaTransport,

	err error) s44.UplinkUEAssociatedLPPaTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkUEAssociatedLPPaTransportIEFieldFreshMust(v s12.UplinkUEAssociatedLPPaTransportIEField, err error) s12.UplinkUEAssociatedLPPaTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkNonUEAssociatedLPPaTransportFreshMust(v s15.DownlinkNonUEAssociatedLPPaTransport,

	err error) s15.DownlinkNonUEAssociatedLPPaTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkNonUEAssociatedLPPaTransportIEFieldFreshMust(v s08.DownlinkNonUEAssociatedLPPaTransportIEField, err error) s08.DownlinkNonUEAssociatedLPPaTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkNonUEAssociatedLPPaTransportFreshMust(v s44.UplinkNonUEAssociatedLPPaTransport,

	err error) s44.UplinkNonUEAssociatedLPPaTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkNonUEAssociatedLPPaTransportIEFieldFreshMust(v s12.UplinkNonUEAssociatedLPPaTransportIEField, err error) s12.UplinkNonUEAssociatedLPPaTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pWSRestartIndicationFreshMust(v s44.PWSRestartIndication,

	err error) s44.PWSRestartIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func pWSRestartIndicationIEFieldFreshMust(v s43.PWSRestartIndicationIEField, err error) s43.PWSRestartIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func rerouteNASRequestFreshMust(v s26.RerouteNASRequest,

	err error) s26.RerouteNASRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func rerouteNASRequestIEFieldFreshMust(v s20.RerouteNASRequestIEField, err error) s20.RerouteNASRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pWSFailureIndicationFreshMust(v s42.PWSFailureIndication,

	err error) s42.PWSFailureIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func pWSFailureIndicationIEFieldFreshMust(v s42.PWSFailureIndicationIEField, err error) s42.PWSFailureIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func connectionEstablishmentIndicationFreshMust(v s31.ConnectionEstablishmentIndication,

	err error) s31.ConnectionEstablishmentIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func connectionEstablishmentIndicationIEFieldFreshMust(v s30.ConnectionEstablishmentIndicationIEField, err error) s30.ConnectionEstablishmentIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func nASDeliveryIndicationFreshMust(v s19.NASDeliveryIndication,

	err error) s19.NASDeliveryIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func nASDeliveryIndicationIEFieldFreshMust(v s10.NASDeliveryIndicationIEField, err error) s10.NASDeliveryIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func retrieveUEInformationFreshMust(v s28.RetrieveUEInformation,

	err error) s28.RetrieveUEInformation {
	if err != nil {
		panic(err)
	}
	return v
}
func retrieveUEInformationIEFieldFreshMust(v s28.RetrieveUEInformationIEField, err error) s28.RetrieveUEInformationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEInformationTransferFreshMust(v s36.UEInformationTransfer,

	err error) s36.UEInformationTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func uEInformationTransferIEFieldFreshMust(v s31.UEInformationTransferIEField, err error) s31.UEInformationTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBCPRelocationIndicationFreshMust(v s37.ENBCPRelocationIndication,

	err error) s37.ENBCPRelocationIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBCPRelocationIndicationIEFieldFreshMust(v s37.ENBCPRelocationIndicationIEField, err error) s37.ENBCPRelocationIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func mMECPRelocationIndicationFreshMust(v s19.MMECPRelocationIndication,

	err error) s19.MMECPRelocationIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func mMECPRelocationIndicationIEFieldFreshMust(v s10.MMECPRelocationIndicationIEField, err error) s10.MMECPRelocationIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func secondaryRATDataUsageReportFreshMust(v s46.SecondaryRATDataUsageReport,

	err error) s46.SecondaryRATDataUsageReport {
	if err != nil {
		panic(err)
	}
	return v
}
func secondaryRATDataUsageReportIEFieldFreshMust(v s45.SecondaryRATDataUsageReportIEField, err error) s45.SecondaryRATDataUsageReportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func secondaryRATDataUsageReportItemIEFieldFreshMust(v s28.SecondaryRATDataUsageReportItemIEField, err error) s28.SecondaryRATDataUsageReportItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABUsageReportItemIEFieldFreshMust(v s17.ERABUsageReportItemIEField, err error) s17.ERABUsageReportItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverSuccessFreshMust(v s18.HandoverSuccess,

	err error) s18.HandoverSuccess {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverSuccessIEFieldFreshMust(v s09.HandoverSuccessIEField, err error) s09.HandoverSuccessIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBEarlyStatusTransferFreshMust(v s37.ENBEarlyStatusTransfer,

	err error) s37.ENBEarlyStatusTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBEarlyStatusTransferIEFieldFreshMust(v s37.ENBEarlyStatusTransferIEField, err error) s37.ENBEarlyStatusTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func bearersSubjectToEarlyStatusTransferItemIEFieldFreshMust(v s15.BearersSubjectToEarlyStatusTransferItemIEField, err error) s15.BearersSubjectToEarlyStatusTransferItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func dLCOUNTPDCPSNlengthFreshMust(v s14.DLCOUNTPDCPSNlength,

	err error) s14.DLCOUNTPDCPSNlength {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEEarlyStatusTransferFreshMust(v s37.MMEEarlyStatusTransfer,

	err error) s37.MMEEarlyStatusTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEEarlyStatusTransferIEFieldFreshMust(v s37.MMEEarlyStatusTransferIEField, err error) s37.MMEEarlyStatusTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func privateMessageIEsValuePrivateIEFieldAPERValueFreshMust(v s25.PrivateMessageIEsValuePrivateIEFieldAPERValue, err error) s25.PrivateMessageIEsValuePrivateIEFieldAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func objectIdentifierFreshMust(v runtime.ObjectIdentifier,

	err error) runtime.ObjectIdentifier {
	if err != nil {
		panic(err)
	}
	return v
}
func ptrDecodeBudgetFreshMust(v *aper.DecodeBudget,

	err error) *aper.DecodeBudget {
	if err != nil {
		panic(err)
	}
	return v
}
func errorIndicationIEFieldFreshMust(v s28.ErrorIndicationIEField, err error) s28.ErrorIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}

type ErrorIndicationSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s28.ErrorIndication, aper.DecodeState,

	) (s28.ErrorIndication, aper.Snapshot,

	)
	compare func(s28.ErrorIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s28.ErrorIndication,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s28.ErrorIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s28.ErrorIndication,

		error)
	inject func(s28.ErrorIndication,

	) s50.SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ErrorIndicationSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ErrorIndicationSuccessfulBinding) Codec() s28.ErrorIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s28.ErrorIndicationValueCodec{}
	}
	return func() s28.ErrorIndicationValueCodec {
		sealed := s28.ErrorIndicationValueCodec{}
		*s28.BridgeErrorIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s28.BridgeErrorIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s28.BridgeErrorIndicationValueCodecFieldEncode(&sealed) = func(value s28.ErrorIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s28.BridgeErrorIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s28.BridgeErrorIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s28.BridgeErrorIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ErrorIndicationSuccessfulBinding) Build(body s28.ErrorIndication,

	options ...aper.BuildOption) (s50.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s50.SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s50.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s50.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s50.SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s50.SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s50.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s50.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s50.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

type ErrorIndicationUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s28.ErrorIndication, aper.DecodeState,

	) (s28.ErrorIndication, aper.Snapshot,

	)
	compare func(s28.ErrorIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s28.ErrorIndication,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s28.ErrorIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s28.ErrorIndication,

		error)
	inject func(s28.ErrorIndication,

	) s36.UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ErrorIndicationUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ErrorIndicationUnsuccessfulBinding) Codec() s28.ErrorIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s28.ErrorIndicationValueCodec{}
	}
	return func() s28.ErrorIndicationValueCodec {
		sealed := s28.ErrorIndicationValueCodec{}
		*s28.BridgeErrorIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s28.BridgeErrorIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s28.BridgeErrorIndicationValueCodecFieldEncode(&sealed) = func(value s28.ErrorIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s28.BridgeErrorIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s28.BridgeErrorIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s28.BridgeErrorIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ErrorIndicationUnsuccessfulBinding) Build(body s28.ErrorIndication,

	options ...aper.BuildOption) (s36.UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s36.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UnsuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UnsuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s36.UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s36.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s36.UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}
func nASPDUAPERValueFreshMust(v s01.NASPDUAPERValue, err error) s01.NASPDUAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func pLMNidentityAPERValueFreshMust(v s01.PLMNidentityAPERValue, err error) s01.PLMNidentityAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func tAIItemIEContainerAPERValueFreshMust(v s33.TAIItemIEContainerAPERValue, err error) s33.TAIItemIEContainerAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func nASPDUSemanticEditRestore(t *testing.T, c s01.NASPDUValueCodec, initial s00.NASPDU,

	edit func(*s00.NASPDU,

	), restore func(*s00.NASPDU,

	)) {
	t.Helper()
	originalEncoder := *s01.BridgeNASPDUValueCodecFieldEncode(&c)
	calls := 0
	*s01.BridgeNASPDUValueCodecFieldEncode(&c) = func(v s00.NASPDU,

		fresh bool, p *aper.DecodeBudget) ([]byte, error) {
		calls++
		return originalEncoder(v, fresh, p)
	}
	wire := sliceByteFreshMust(c.EncodeAPER(nASPDUAPERValueFreshMust(c.New(initial))))
	calls = 0
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("complete decode called value encoder")
	}
	original := append([]byte(nil), wire...)
	for i := range wire {
		wire[i] ^= 0xff
	}
	if got := sliceByteFreshMust(c.EncodeAPER(v)); !bytes.Equal(got, original) {
		t.Fatal("decoder borrowed caller input")
	}
	if calls != 0 {
		t.Fatal("unchanged complete encode called value encoder")
	}
	edit(&v.Value)
	got := sliceByteFreshMust(c.EncodeAPER(v))
	want := sliceByteFreshMust(c.EncodeAPER(v, aper.WithoutReplay()))
	if bytes.Equal(got, original) || !bytes.Equal(got, want) {
		t.Fatal("edited semantics did not reach complete encoder")
	}
	beforeRestore := calls
	restore(&v.Value)
	if got := sliceByteFreshMust(c.EncodeAPER(v)); !bytes.Equal(got, original) {
		t.Fatal("restored value did not replay")
	}
	if calls != beforeRestore {
		t.Fatal("restored complete encode called value encoder")
	}
}
func transportLayerAddressSemanticEditRestore(t *testing.T, c s02.TransportLayerAddressValueCodec, initial s00.TransportLayerAddress,

	edit func(*s00.TransportLayerAddress,

	), restore func(*s00.TransportLayerAddress,

	)) {
	t.Helper()
	originalEncoder := *s02.BridgeTransportLayerAddressValueCodecFieldEncode(&c)
	calls := 0
	*s02.BridgeTransportLayerAddressValueCodecFieldEncode(&c) = func(v s00.TransportLayerAddress,

		fresh bool, p *aper.DecodeBudget) ([]byte, error) {
		calls++
		return originalEncoder(v, fresh, p)
	}
	wire := sliceByteFreshMust(c.EncodeAPER(transportLayerAddressAPERValueFreshMust(c.New(initial))))
	calls = 0
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("complete decode called value encoder")
	}
	original := append([]byte(nil), wire...)
	for i := range wire {
		wire[i] ^= 0xff
	}
	if got := sliceByteFreshMust(c.EncodeAPER(v)); !bytes.Equal(got, original) {
		t.Fatal("decoder borrowed caller input")
	}
	if calls != 0 {
		t.Fatal("unchanged complete encode called value encoder")
	}
	edit(&v.Value)
	got := sliceByteFreshMust(c.EncodeAPER(v))
	want := sliceByteFreshMust(c.EncodeAPER(v, aper.WithoutReplay()))
	if bytes.Equal(got, original) || !bytes.Equal(got, want) {
		t.Fatal("edited semantics did not reach complete encoder")
	}
	beforeRestore := calls
	restore(&v.Value)
	if got := sliceByteFreshMust(c.EncodeAPER(v)); !bytes.Equal(got, original) {
		t.Fatal("restored value did not replay")
	}
	if calls != beforeRestore {
		t.Fatal("restored complete encode called value encoder")
	}
}
func eHRPDSectorCapacityClassValueSemanticEditRestore(t *testing.T, c s00.EHRPDSectorCapacityClassValueValueCodec, initial s00.EHRPDSectorCapacityClassValue,

	edit func(*s00.EHRPDSectorCapacityClassValue,

	), restore func(*s00.EHRPDSectorCapacityClassValue,

	)) {
	t.Helper()
	originalEncoder := *s00.BridgeEHRPDSectorCapacityClassValueValueCodecFieldEncode(&c)
	calls := 0
	*s00.BridgeEHRPDSectorCapacityClassValueValueCodecFieldEncode(&c) = func(v s00.EHRPDSectorCapacityClassValue,

		fresh bool, p *aper.DecodeBudget) ([]byte, error) {
		calls++
		return originalEncoder(v, fresh, p)
	}
	wire := sliceByteFreshMust(c.EncodeAPER(eHRPDSectorCapacityClassValueAPERValueFreshMust(c.New(initial))))
	calls = 0
	v, _, err := c.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("complete decode called value encoder")
	}
	original := append([]byte(nil), wire...)
	for i := range wire {
		wire[i] ^= 0xff
	}
	if got := sliceByteFreshMust(c.EncodeAPER(v)); !bytes.Equal(got, original) {
		t.Fatal("decoder borrowed caller input")
	}
	if calls != 0 {
		t.Fatal("unchanged complete encode called value encoder")
	}
	edit(&v.Value)
	got := sliceByteFreshMust(c.EncodeAPER(v))
	want := sliceByteFreshMust(c.EncodeAPER(v, aper.WithoutReplay()))
	if bytes.Equal(got, original) || !bytes.Equal(got, want) {
		t.Fatal("edited semantics did not reach complete encoder")
	}
	beforeRestore := calls
	restore(&v.Value)
	if got := sliceByteFreshMust(c.EncodeAPER(v)); !bytes.Equal(got, original) {
		t.Fatal("restored value did not replay")
	}
	if calls != beforeRestore {
		t.Fatal("restored complete encode called value encoder")
	}
}

type Int64ValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (int64,

		error)
	encode func(int64,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(int64, aper.DecodeState,

	) (int64, aper.Snapshot,

	)
	compare func(int64, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c Int64ValueCodec) New(value int64,

) (Int64APERValue, error) {
	if c.encode == nil {
		return Int64APERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return Int64APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return Int64APERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return Int64APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c Int64ValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (Int64APERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return Int64APERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return Int64APERValue{}, report, aper.OperationError(err, c.path)
		}
		return Int64APERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return Int64APERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c Int64ValueCodec) EncodeAPER(value Int64APERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c Int64ValueCodec) encodeBudgetValue(value int64,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c Int64ValueCodec) encodeChanged(value int64,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func transportLayerAddressAPERValueFreshMust(v s02.TransportLayerAddressAPERValue, err error) s02.TransportLayerAddressAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func criticalityDiagnosticsCheckFreshCodec(t *testing.T, codec s22.CriticalityDiagnosticsValueCodec, wire, preferred []byte) {
	t.Helper()
	if bytes.Equal(wire, preferred) {
		t.Fatal("fixture has no representation difference")
	}
	owned, _, err := codec.DecodeAPER(wire)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := codec.EncodeAPER(owned)
	if err != nil || !bytes.Equal(replay, wire) {
		t.Fatalf("replay=%x err=%v", replay, err)
	}
	for _, fresh := range []bool{false, true} {
		value := owned
		var opts []aper.EncodeOption
		if fresh {
			value = value.WithoutReplay()
		} else {
			opts = []aper.EncodeOption{aper.WithoutReplay()}
		}
		got, err := codec.EncodeAPER(value, opts...)
		if err != nil || !bytes.Equal(got, preferred) {
			t.Fatalf("fresh=%x err=%v want=%x", got, err, preferred)
		}
	}
	again, err := codec.EncodeAPER(owned)
	if err != nil || !bytes.Equal(again, wire) {
		t.Fatal("fresh damaged default replay")
	}
}
func choiceExtensionFreshMust(v aper.ChoiceExtension,

	err error) aper.ChoiceExtension {
	if err != nil {
		panic(err)
	}
	return v
}
func cellTrafficTraceIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s17.CellTrafficTraceIEField) {
	t.Helper()
	zero := s17.CellTrafficTraceIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeCellTrafficTraceIEValueValidateS1APIEContainer(s17.CellTrafficTraceIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s17.BridgeCellTrafficTraceIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s17.CellTrafficTraceIEField{selected, opaque} {
		if !s17.BridgeCellTrafficTraceIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s17.BridgeCellTrafficTraceIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func connectionEstablishmentIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s30.ConnectionEstablishmentIndicationIEField) {
	t.Helper()
	zero := s30.ConnectionEstablishmentIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s31.BridgeConnectionEstablishmentIndicationIEValueValidateS1APIEContainer(s30.ConnectionEstablishmentIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s30.BridgeConnectionEstablishmentIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s30.ConnectionEstablishmentIndicationIEField{selected, opaque} {
		if !s30.BridgeConnectionEstablishmentIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s30.BridgeConnectionEstablishmentIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func deactivateTraceIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s08.DeactivateTraceIEField) {
	t.Helper()
	zero := s08.DeactivateTraceIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeDeactivateTraceIEValueValidateS1APIEContainer(s08.DeactivateTraceIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s08.BridgeDeactivateTraceIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s08.DeactivateTraceIEField{selected, opaque} {
		if !s08.BridgeDeactivateTraceIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s08.BridgeDeactivateTraceIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func downlinkNASTransportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s42.DownlinkNASTransportIEField) {
	t.Helper()
	zero := s42.DownlinkNASTransportIEField{Id: 0, Criticality: selected.Criticality}
	report := s42.BridgeDownlinkNASTransportIEValueValidateS1APIEContainer(s42.DownlinkNASTransportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s42.BridgeDownlinkNASTransportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s42.DownlinkNASTransportIEField{selected, opaque} {
		if !s42.BridgeDownlinkNASTransportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s42.BridgeDownlinkNASTransportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func downlinkS1cdma2000tunnellingIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s40.DownlinkS1cdma2000tunnellingIEField) {
	t.Helper()
	zero := s40.DownlinkS1cdma2000tunnellingIEField{Id: 0, Criticality: selected.Criticality}
	report := s40.BridgeDownlinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(s40.DownlinkS1cdma2000tunnellingIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s40.BridgeDownlinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s40.DownlinkS1cdma2000tunnellingIEField{selected, opaque} {
		if !s40.BridgeDownlinkS1cdma2000tunnellingIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s40.BridgeDownlinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func downlinkUEAssociatedLPPaTransportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s08.DownlinkUEAssociatedLPPaTransportIEField) {
	t.Helper()
	zero := s08.DownlinkUEAssociatedLPPaTransportIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeDownlinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(s08.DownlinkUEAssociatedLPPaTransportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s08.DownlinkUEAssociatedLPPaTransportIEField{selected, opaque} {
		if !s08.BridgeDownlinkUEAssociatedLPPaTransportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s08.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABModificationConfirmIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s39.ERABModificationConfirmIEField) {
	t.Helper()
	zero := s39.ERABModificationConfirmIEField{Id: 0, Criticality: selected.Criticality}
	report := s39.BridgeERABModificationConfirmIEValueValidateS1APIEContainer(s39.ERABModificationConfirmIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s39.BridgeERABModificationConfirmIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s39.ERABModificationConfirmIEField{selected, opaque} {
		if !s39.BridgeERABModificationConfirmIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s39.BridgeERABModificationConfirmIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABModificationIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s44.ERABModificationIndicationIEField) {
	t.Helper()
	zero := s44.ERABModificationIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s45.BridgeERABModificationIndicationIEValueValidateS1APIEContainer(s44.ERABModificationIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s44.BridgeERABModificationIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s44.ERABModificationIndicationIEField{selected, opaque} {
		if !s44.BridgeERABModificationIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s44.BridgeERABModificationIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABModifyRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s40.ERABModifyRequestIEField) {
	t.Helper()
	zero := s40.ERABModifyRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s40.BridgeERABModifyRequestIEValueValidateS1APIEContainer(s40.ERABModifyRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s40.BridgeERABModifyRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s40.ERABModifyRequestIEField{selected, opaque} {
		if !s40.BridgeERABModifyRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s40.BridgeERABModifyRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABModifyResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s44.ERABModifyResponseIEField) {
	t.Helper()
	zero := s44.ERABModifyResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s45.BridgeERABModifyResponseIEValueValidateS1APIEContainer(s44.ERABModifyResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s44.BridgeERABModifyResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s44.ERABModifyResponseIEField{selected, opaque} {
		if !s44.BridgeERABModifyResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s44.BridgeERABModifyResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABReleaseCommandIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s39.ERABReleaseCommandIEField) {
	t.Helper()
	zero := s39.ERABReleaseCommandIEField{Id: 0, Criticality: selected.Criticality}
	report := s39.BridgeERABReleaseCommandIEValueValidateS1APIEContainer(s39.ERABReleaseCommandIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s39.BridgeERABReleaseCommandIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s39.ERABReleaseCommandIEField{selected, opaque} {
		if !s39.BridgeERABReleaseCommandIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s39.BridgeERABReleaseCommandIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABReleaseIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s44.ERABReleaseIndicationIEField) {
	t.Helper()
	zero := s44.ERABReleaseIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s45.BridgeERABReleaseIndicationIEValueValidateS1APIEContainer(s44.ERABReleaseIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s44.BridgeERABReleaseIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s44.ERABReleaseIndicationIEField{selected, opaque} {
		if !s44.BridgeERABReleaseIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s44.BridgeERABReleaseIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABReleaseResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s45.ERABReleaseResponseIEField) {
	t.Helper()
	zero := s45.ERABReleaseResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeERABReleaseResponseIEValueValidateS1APIEContainer(s45.ERABReleaseResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s45.BridgeERABReleaseResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s45.ERABReleaseResponseIEField{selected, opaque} {
		if !s45.BridgeERABReleaseResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s45.BridgeERABReleaseResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABSetupRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s40.ERABSetupRequestIEField) {
	t.Helper()
	zero := s40.ERABSetupRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s40.BridgeERABSetupRequestIEValueValidateS1APIEContainer(s40.ERABSetupRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s40.BridgeERABSetupRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s40.ERABSetupRequestIEField{selected, opaque} {
		if !s40.BridgeERABSetupRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s40.BridgeERABSetupRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABSetupResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s45.ERABSetupResponseIEField) {
	t.Helper()
	zero := s45.ERABSetupResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeERABSetupResponseIEValueValidateS1APIEContainer(s45.ERABSetupResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s45.BridgeERABSetupResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s45.ERABSetupResponseIEField{selected, opaque} {
		if !s45.BridgeERABSetupResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s45.BridgeERABSetupResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eNBEarlyStatusTransferIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s37.ENBEarlyStatusTransferIEField) {
	t.Helper()
	zero := s37.ENBEarlyStatusTransferIEField{Id: 0, Criticality: selected.Criticality}
	report := s37.BridgeENBEarlyStatusTransferIEValueValidateS1APIEContainer(s37.ENBEarlyStatusTransferIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s37.BridgeENBEarlyStatusTransferIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s37.ENBEarlyStatusTransferIEField{selected, opaque} {
		if !s37.BridgeENBEarlyStatusTransferIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s37.BridgeENBEarlyStatusTransferIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eNBStatusTransferIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s21.ENBStatusTransferIEField) {
	t.Helper()
	zero := s21.ENBStatusTransferIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeENBStatusTransferIEValueValidateS1APIEContainer(s21.ENBStatusTransferIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s21.BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s21.ENBStatusTransferIEField{selected, opaque} {
		if !s21.BridgeENBStatusTransferIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s21.BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func errorIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s28.ErrorIndicationIEField) {
	t.Helper()
	zero := s28.ErrorIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s28.BridgeErrorIndicationIEValueValidateS1APIEContainer(s28.ErrorIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s28.BridgeErrorIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s28.ErrorIndicationIEField{selected, opaque} {
		if !s28.BridgeErrorIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s28.BridgeErrorIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverCancelAcknowledgeIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s22.HandoverCancelAcknowledgeIEField) {
	t.Helper()
	zero := s22.HandoverCancelAcknowledgeIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeHandoverCancelAcknowledgeIEValueValidateS1APIEContainer(s22.HandoverCancelAcknowledgeIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s22.BridgeHandoverCancelAcknowledgeIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s22.HandoverCancelAcknowledgeIEField{selected, opaque} {
		if !s22.BridgeHandoverCancelAcknowledgeIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s22.BridgeHandoverCancelAcknowledgeIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverCancelIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s18.HandoverCancelIEField) {
	t.Helper()
	zero := s18.HandoverCancelIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeHandoverCancelIEValueValidateS1APIEContainer(s18.HandoverCancelIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s18.BridgeHandoverCancelIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s18.HandoverCancelIEField{selected, opaque} {
		if !s18.BridgeHandoverCancelIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s18.BridgeHandoverCancelIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverCommandIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s40.HandoverCommandIEField) {
	t.Helper()
	zero := s40.HandoverCommandIEField{Id: 0, Criticality: selected.Criticality}
	report := s40.BridgeHandoverCommandIEValueValidateS1APIEContainer(s40.HandoverCommandIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s40.BridgeHandoverCommandIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s40.HandoverCommandIEField{selected, opaque} {
		if !s40.BridgeHandoverCommandIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s40.BridgeHandoverCommandIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s22.HandoverFailureIEField) {
	t.Helper()
	zero := s22.HandoverFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeHandoverFailureIEValueValidateS1APIEContainer(s22.HandoverFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s22.BridgeHandoverFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s22.HandoverFailureIEField{selected, opaque} {
		if !s22.BridgeHandoverFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s22.BridgeHandoverFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverNotifyIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s35.HandoverNotifyIEField) {
	t.Helper()
	zero := s35.HandoverNotifyIEField{Id: 0, Criticality: selected.Criticality}
	report := s35.BridgeHandoverNotifyIEValueValidateS1APIEContainer(s35.HandoverNotifyIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s35.BridgeHandoverNotifyIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s35.HandoverNotifyIEField{selected, opaque} {
		if !s35.BridgeHandoverNotifyIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s35.BridgeHandoverNotifyIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverPreparationFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s22.HandoverPreparationFailureIEField) {
	t.Helper()
	zero := s22.HandoverPreparationFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeHandoverPreparationFailureIEValueValidateS1APIEContainer(s22.HandoverPreparationFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s22.BridgeHandoverPreparationFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s22.HandoverPreparationFailureIEField{selected, opaque} {
		if !s22.BridgeHandoverPreparationFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s22.BridgeHandoverPreparationFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverRequestAcknowledgeIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s38.HandoverRequestAcknowledgeIEField) {
	t.Helper()
	zero := s38.HandoverRequestAcknowledgeIEField{Id: 0, Criticality: selected.Criticality}
	report := s39.BridgeHandoverRequestAcknowledgeIEValueValidateS1APIEContainer(s38.HandoverRequestAcknowledgeIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s38.BridgeHandoverRequestAcknowledgeIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s38.HandoverRequestAcknowledgeIEField{selected, opaque} {
		if !s38.BridgeHandoverRequestAcknowledgeIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s38.BridgeHandoverRequestAcknowledgeIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s47.HandoverRequestIEField) {
	t.Helper()
	zero := s47.HandoverRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s48.BridgeHandoverRequestIEValueValidateS1APIEContainer(s47.HandoverRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s47.BridgeHandoverRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s47.HandoverRequestIEField{selected, opaque} {
		if !s47.BridgeHandoverRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s47.BridgeHandoverRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverRequiredIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s34.HandoverRequiredIEField) {
	t.Helper()
	zero := s34.HandoverRequiredIEField{Id: 0, Criticality: selected.Criticality}
	report := s34.BridgeHandoverRequiredIEValueValidateS1APIEContainer(s34.HandoverRequiredIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s34.BridgeHandoverRequiredIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s34.HandoverRequiredIEField{selected, opaque} {
		if !s34.BridgeHandoverRequiredIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s34.BridgeHandoverRequiredIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverSuccessIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s09.HandoverSuccessIEField) {
	t.Helper()
	zero := s09.HandoverSuccessIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeHandoverSuccessIEValueValidateS1APIEContainer(s09.HandoverSuccessIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s09.BridgeHandoverSuccessIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s09.HandoverSuccessIEField{selected, opaque} {
		if !s09.BridgeHandoverSuccessIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s09.BridgeHandoverSuccessIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func initialContextSetupFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s22.InitialContextSetupFailureIEField) {
	t.Helper()
	zero := s22.InitialContextSetupFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeInitialContextSetupFailureIEValueValidateS1APIEContainer(s22.InitialContextSetupFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s22.BridgeInitialContextSetupFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s22.InitialContextSetupFailureIEField{selected, opaque} {
		if !s22.BridgeInitialContextSetupFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s22.BridgeInitialContextSetupFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func initialContextSetupRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s48.InitialContextSetupRequestIEField) {
	t.Helper()
	zero := s48.InitialContextSetupRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s48.BridgeInitialContextSetupRequestIEValueValidateS1APIEContainer(s48.InitialContextSetupRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s48.BridgeInitialContextSetupRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s48.InitialContextSetupRequestIEField{selected, opaque} {
		if !s48.BridgeInitialContextSetupRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s48.BridgeInitialContextSetupRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func initialContextSetupResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s39.InitialContextSetupResponseIEField) {
	t.Helper()
	zero := s39.InitialContextSetupResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s39.BridgeInitialContextSetupResponseIEValueValidateS1APIEContainer(s39.InitialContextSetupResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s39.BridgeInitialContextSetupResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s39.InitialContextSetupResponseIEField{selected, opaque} {
		if !s39.BridgeInitialContextSetupResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s39.BridgeInitialContextSetupResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func locationReportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s31.LocationReportIEField) {
	t.Helper()
	zero := s31.LocationReportIEField{Id: 0, Criticality: selected.Criticality}
	report := s33.BridgeLocationReportIEValueValidateS1APIEContainer(s31.LocationReportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s31.BridgeLocationReportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s31.LocationReportIEField{selected, opaque} {
		if !s31.BridgeLocationReportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s31.BridgeLocationReportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func locationReportingControlIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s26.LocationReportingControlIEField) {
	t.Helper()
	zero := s26.LocationReportingControlIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeLocationReportingControlIEValueValidateS1APIEContainer(s26.LocationReportingControlIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s26.BridgeLocationReportingControlIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s26.LocationReportingControlIEField{selected, opaque} {
		if !s26.BridgeLocationReportingControlIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s26.BridgeLocationReportingControlIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func locationReportingFailureIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s18.LocationReportingFailureIndicationIEField) {
	t.Helper()
	zero := s18.LocationReportingFailureIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeLocationReportingFailureIndicationIEValueValidateS1APIEContainer(s18.LocationReportingFailureIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s18.BridgeLocationReportingFailureIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s18.LocationReportingFailureIndicationIEField{selected, opaque} {
		if !s18.BridgeLocationReportingFailureIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s18.BridgeLocationReportingFailureIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func mMECPRelocationIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s10.MMECPRelocationIndicationIEField) {
	t.Helper()
	zero := s10.MMECPRelocationIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeMMECPRelocationIndicationIEValueValidateS1APIEContainer(s10.MMECPRelocationIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s10.BridgeMMECPRelocationIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s10.MMECPRelocationIndicationIEField{selected, opaque} {
		if !s10.BridgeMMECPRelocationIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s10.BridgeMMECPRelocationIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func mMEEarlyStatusTransferIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s37.MMEEarlyStatusTransferIEField) {
	t.Helper()
	zero := s37.MMEEarlyStatusTransferIEField{Id: 0, Criticality: selected.Criticality}
	report := s38.BridgeMMEEarlyStatusTransferIEValueValidateS1APIEContainer(s37.MMEEarlyStatusTransferIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s37.BridgeMMEEarlyStatusTransferIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s37.MMEEarlyStatusTransferIEField{selected, opaque} {
		if !s37.BridgeMMEEarlyStatusTransferIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s37.BridgeMMEEarlyStatusTransferIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func mMEStatusTransferIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s21.MMEStatusTransferIEField) {
	t.Helper()
	zero := s21.MMEStatusTransferIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeMMEStatusTransferIEValueValidateS1APIEContainer(s21.MMEStatusTransferIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s21.BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s21.MMEStatusTransferIEField{selected, opaque} {
		if !s21.BridgeMMEStatusTransferIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s21.BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func nASDeliveryIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s10.NASDeliveryIndicationIEField) {
	t.Helper()
	zero := s10.NASDeliveryIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeNASDeliveryIndicationIEValueValidateS1APIEContainer(s10.NASDeliveryIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s10.BridgeNASDeliveryIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s10.NASDeliveryIndicationIEField{selected, opaque} {
		if !s10.BridgeNASDeliveryIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s10.BridgeNASDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func nASNonDeliveryIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s19.NASNonDeliveryIndicationIEField) {
	t.Helper()
	zero := s19.NASNonDeliveryIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeNASNonDeliveryIndicationIEValueValidateS1APIEContainer(s19.NASNonDeliveryIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s19.NASNonDeliveryIndicationIEField{selected, opaque} {
		if !s19.BridgeNASNonDeliveryIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s19.BridgeNASNonDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func pathSwitchRequestAcknowledgeIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s46.PathSwitchRequestAcknowledgeIEField) {
	t.Helper()
	zero := s46.PathSwitchRequestAcknowledgeIEField{Id: 0, Criticality: selected.Criticality}
	report := s47.BridgePathSwitchRequestAcknowledgeIEValueValidateS1APIEContainer(s46.PathSwitchRequestAcknowledgeIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s46.BridgePathSwitchRequestAcknowledgeIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s46.PathSwitchRequestAcknowledgeIEField{selected, opaque} {
		if !s46.BridgePathSwitchRequestAcknowledgeIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s46.BridgePathSwitchRequestAcknowledgeIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func pathSwitchRequestFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s23.PathSwitchRequestFailureIEField) {
	t.Helper()
	zero := s23.PathSwitchRequestFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgePathSwitchRequestFailureIEValueValidateS1APIEContainer(s23.PathSwitchRequestFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s23.BridgePathSwitchRequestFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s23.PathSwitchRequestFailureIEField{selected, opaque} {
		if !s23.BridgePathSwitchRequestFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s23.BridgePathSwitchRequestFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func rerouteNASRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s20.RerouteNASRequestIEField) {
	t.Helper()
	zero := s20.RerouteNASRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s27.BridgeRerouteNASRequestIEValueValidateS1APIEContainer(s20.RerouteNASRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s20.BridgeRerouteNASRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s20.RerouteNASRequestIEField{selected, opaque} {
		if !s20.BridgeRerouteNASRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s20.BridgeRerouteNASRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func secondaryRATDataUsageReportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s45.SecondaryRATDataUsageReportIEField) {
	t.Helper()
	zero := s45.SecondaryRATDataUsageReportIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeSecondaryRATDataUsageReportIEValueValidateS1APIEContainer(s45.SecondaryRATDataUsageReportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s45.BridgeSecondaryRATDataUsageReportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s45.SecondaryRATDataUsageReportIEField{selected, opaque} {
		if !s45.BridgeSecondaryRATDataUsageReportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s45.BridgeSecondaryRATDataUsageReportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func traceFailureIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s20.TraceFailureIndicationIEField) {
	t.Helper()
	zero := s20.TraceFailureIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s34.BridgeTraceFailureIndicationIEValueValidateS1APIEContainer(s20.TraceFailureIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s20.BridgeTraceFailureIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s20.TraceFailureIndicationIEField{selected, opaque} {
		if !s20.BridgeTraceFailureIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s20.BridgeTraceFailureIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func traceStartIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s48.TraceStartIEField) {
	t.Helper()
	zero := s48.TraceStartIEField{Id: 0, Criticality: selected.Criticality}
	report := s48.BridgeTraceStartIEValueValidateS1APIEContainer(s48.TraceStartIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s48.BridgeTraceStartIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s48.TraceStartIEField{selected, opaque} {
		if !s48.BridgeTraceStartIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s48.BridgeTraceStartIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uECapabilityInfoIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s12.UECapabilityInfoIndicationIEField) {
	t.Helper()
	zero := s12.UECapabilityInfoIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s36.BridgeUECapabilityInfoIndicationIEValueValidateS1APIEContainer(s12.UECapabilityInfoIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s12.UECapabilityInfoIndicationIEField{selected, opaque} {
		if !s12.BridgeUECapabilityInfoIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextModificationConfirmIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s23.UEContextModificationConfirmIEField) {
	t.Helper()
	zero := s23.UEContextModificationConfirmIEField{Id: 0, Criticality: selected.Criticality}
	report := s36.BridgeUEContextModificationConfirmIEValueValidateS1APIEContainer(s23.UEContextModificationConfirmIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s23.BridgeUEContextModificationConfirmIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s23.UEContextModificationConfirmIEField{selected, opaque} {
		if !s23.BridgeUEContextModificationConfirmIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s23.BridgeUEContextModificationConfirmIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextModificationFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s23.UEContextModificationFailureIEField) {
	t.Helper()
	zero := s23.UEContextModificationFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s36.BridgeUEContextModificationFailureIEValueValidateS1APIEContainer(s23.UEContextModificationFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s23.BridgeUEContextModificationFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s23.UEContextModificationFailureIEField{selected, opaque} {
		if !s23.BridgeUEContextModificationFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s23.BridgeUEContextModificationFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextModificationIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s21.UEContextModificationIndicationIEField) {
	t.Helper()
	zero := s21.UEContextModificationIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s36.BridgeUEContextModificationIndicationIEValueValidateS1APIEContainer(s21.UEContextModificationIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s21.BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s21.UEContextModificationIndicationIEField{selected, opaque} {
		if !s21.BridgeUEContextModificationIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s21.BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextModificationRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s46.UEContextModificationRequestIEField) {
	t.Helper()
	zero := s46.UEContextModificationRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s47.BridgeUEContextModificationRequestIEValueValidateS1APIEContainer(s46.UEContextModificationRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s46.BridgeUEContextModificationRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s46.UEContextModificationRequestIEField{selected, opaque} {
		if !s46.BridgeUEContextModificationRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s46.BridgeUEContextModificationRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextModificationResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s23.UEContextModificationResponseIEField) {
	t.Helper()
	zero := s23.UEContextModificationResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s36.BridgeUEContextModificationResponseIEValueValidateS1APIEContainer(s23.UEContextModificationResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s23.BridgeUEContextModificationResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s23.UEContextModificationResponseIEField{selected, opaque} {
		if !s23.BridgeUEContextModificationResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s23.BridgeUEContextModificationResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextReleaseCompleteIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s45.UEContextReleaseCompleteIEField) {
	t.Helper()
	zero := s45.UEContextReleaseCompleteIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeUEContextReleaseCompleteIEValueValidateS1APIEContainer(s45.UEContextReleaseCompleteIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s45.BridgeUEContextReleaseCompleteIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s45.UEContextReleaseCompleteIEField{selected, opaque} {
		if !s45.BridgeUEContextReleaseCompleteIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s45.BridgeUEContextReleaseCompleteIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextReleaseRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s42.UEContextReleaseRequestIEField) {
	t.Helper()
	zero := s42.UEContextReleaseRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s42.BridgeUEContextReleaseRequestIEValueValidateS1APIEContainer(s42.UEContextReleaseRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s42.BridgeUEContextReleaseRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s42.UEContextReleaseRequestIEField{selected, opaque} {
		if !s42.BridgeUEContextReleaseRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s42.BridgeUEContextReleaseRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextResumeFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s23.UEContextResumeFailureIEField) {
	t.Helper()
	zero := s23.UEContextResumeFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s36.BridgeUEContextResumeFailureIEValueValidateS1APIEContainer(s23.UEContextResumeFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s23.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s23.UEContextResumeFailureIEField{selected, opaque} {
		if !s23.BridgeUEContextResumeFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s23.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextResumeRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s38.UEContextResumeRequestIEField) {
	t.Helper()
	zero := s38.UEContextResumeRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s38.BridgeUEContextResumeRequestIEValueValidateS1APIEContainer(s38.UEContextResumeRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s38.BridgeUEContextResumeRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s38.UEContextResumeRequestIEField{selected, opaque} {
		if !s38.BridgeUEContextResumeRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s38.BridgeUEContextResumeRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextResumeResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s38.UEContextResumeResponseIEField) {
	t.Helper()
	zero := s38.UEContextResumeResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s38.BridgeUEContextResumeResponseIEValueValidateS1APIEContainer(s38.UEContextResumeResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s38.BridgeUEContextResumeResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s38.UEContextResumeResponseIEField{selected, opaque} {
		if !s38.BridgeUEContextResumeResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s38.BridgeUEContextResumeResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextSuspendRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s45.UEContextSuspendRequestIEField) {
	t.Helper()
	zero := s45.UEContextSuspendRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeUEContextSuspendRequestIEValueValidateS1APIEContainer(s45.UEContextSuspendRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s45.BridgeUEContextSuspendRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s45.UEContextSuspendRequestIEField{selected, opaque} {
		if !s45.BridgeUEContextSuspendRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s45.BridgeUEContextSuspendRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextSuspendResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s28.UEContextSuspendResponseIEField) {
	t.Helper()
	zero := s28.UEContextSuspendResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s36.BridgeUEContextSuspendResponseIEValueValidateS1APIEContainer(s28.UEContextSuspendResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s28.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s28.UEContextSuspendResponseIEField{selected, opaque} {
		if !s28.BridgeUEContextSuspendResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s28.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uERadioCapabilityMatchRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s12.UERadioCapabilityMatchRequestIEField) {
	t.Helper()
	zero := s12.UERadioCapabilityMatchRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s36.BridgeUERadioCapabilityMatchRequestIEValueValidateS1APIEContainer(s12.UERadioCapabilityMatchRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s12.UERadioCapabilityMatchRequestIEField{selected, opaque} {
		if !s12.BridgeUERadioCapabilityMatchRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uERadioCapabilityMatchResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s24.UERadioCapabilityMatchResponseIEField) {
	t.Helper()
	zero := s24.UERadioCapabilityMatchResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s36.BridgeUERadioCapabilityMatchResponseIEValueValidateS1APIEContainer(s24.UERadioCapabilityMatchResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s24.UERadioCapabilityMatchResponseIEField{selected, opaque} {
		if !s24.BridgeUERadioCapabilityMatchResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uplinkNASTransportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s32.UplinkNASTransportIEField) {
	t.Helper()
	zero := s32.UplinkNASTransportIEField{Id: 0, Criticality: selected.Criticality}
	report := s44.BridgeUplinkNASTransportIEValueValidateS1APIEContainer(s32.UplinkNASTransportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s32.BridgeUplinkNASTransportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s32.UplinkNASTransportIEField{selected, opaque} {
		if !s32.BridgeUplinkNASTransportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s32.BridgeUplinkNASTransportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uplinkS1cdma2000tunnellingIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s21.UplinkS1cdma2000tunnellingIEField) {
	t.Helper()
	zero := s21.UplinkS1cdma2000tunnellingIEField{Id: 0, Criticality: selected.Criticality}
	report := s44.BridgeUplinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(s21.UplinkS1cdma2000tunnellingIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s21.BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s21.UplinkS1cdma2000tunnellingIEField{selected, opaque} {
		if !s21.BridgeUplinkS1cdma2000tunnellingIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s21.BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uplinkUEAssociatedLPPaTransportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s12.UplinkUEAssociatedLPPaTransportIEField) {
	t.Helper()
	zero := s12.UplinkUEAssociatedLPPaTransportIEField{Id: 0, Criticality: selected.Criticality}
	report := s44.BridgeUplinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(s12.UplinkUEAssociatedLPPaTransportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s12.UplinkUEAssociatedLPPaTransportIEField{selected, opaque} {
		if !s12.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s12.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eHRPDSectorCapacityClassValueAPERValueFreshMust(v s00.EHRPDSectorCapacityClassValueAPERValue, err error) s00.EHRPDSectorCapacityClassValueAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}

type Int64APERValue struct {
	context s00.BridgeCodecContext
	Value   int64

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v Int64APERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v Int64APERValue) WithoutReplay() Int64APERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
